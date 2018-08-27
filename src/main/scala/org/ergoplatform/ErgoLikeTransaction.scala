package org.ergoplatform

import scorex.crypto.authds.ADKey
import scorex.crypto.hash.{Blake2b256, Digest32}
import scorex.util._
import sigmastate.interpreter.ProverResult
import sigmastate.serialization.Serializer
import sigmastate.serialization.Serializer.{Consumed, Position}

import scala.util.Try
import org.ergoplatform.ErgoBox.BoxId


trait ErgoBoxReader {
  def byId(boxId: ADKey): Try[ErgoBox]
}


trait ErgoLikeTransactionTemplate[IT <: UnsignedInput] {
  val inputs: IndexedSeq[IT]
  val outputCandidates: IndexedSeq[ErgoBoxCandidate]

  require(outputCandidates.size <= Short.MaxValue)

  val id: ModifierId

  lazy val outputs: IndexedSeq[ErgoBox] =
    outputCandidates.indices.map(idx => outputCandidates(idx).toBox(id, idx.toShort))

  lazy val messageToSign: Array[Byte] =
    ErgoLikeTransaction.flattenedTxSerializer.bytesToSign(inputs.map(_.boxId), outputCandidates)

  lazy val inputIds: IndexedSeq[ADKey] = inputs.map(_.boxId)
}


class UnsignedErgoLikeTransaction(override val inputs: IndexedSeq[UnsignedInput],
                                  override val outputCandidates: IndexedSeq[ErgoBoxCandidate])
  extends ErgoLikeTransactionTemplate[UnsignedInput] {

  override val id: ModifierId = Blake2b256.hash(messageToSign).toModifierId

  def toSigned(proofs: IndexedSeq[ProverResult]): ErgoLikeTransaction = {
    require(proofs.size == inputs.size)
    val ins = inputs.zip(proofs).map { case (ui, proof) => Input(ui.boxId, proof) }
    new ErgoLikeTransaction(ins, outputCandidates)
  }
}

object UnsignedErgoLikeTransaction {
  def apply(inputs: IndexedSeq[UnsignedInput], outputCandidates: IndexedSeq[ErgoBoxCandidate]) =
    new UnsignedErgoLikeTransaction(inputs, outputCandidates)
}

/**
  * Fully signed transaction
  *
  * @param inputs
  * @param outputCandidates
  */
class ErgoLikeTransaction(override val inputs: IndexedSeq[Input],
                          override val outputCandidates: IndexedSeq[ErgoBoxCandidate])
  extends ErgoLikeTransactionTemplate[Input] {

  require(outputCandidates.length <= Short.MaxValue, s"${Short.MaxValue} is the maximum number of outputs")

  override val id: ModifierId = Blake2b256.hash(messageToSign).toModifierId

  override def equals(obj: Any): Boolean = obj match {
    //we're ignoring spending proofs here
    case tx: ErgoLikeTransaction => this.id == tx.id
    case _ => false
  }

  override def hashCode(): Int = id.hashCode()
}


object ErgoLikeTransaction {
  def apply(inputs: IndexedSeq[Input], outputCandidates: IndexedSeq[ErgoBoxCandidate]) =
    new ErgoLikeTransaction(inputs, outputCandidates)

  type FlattenedTransaction = (IndexedSeq[Input], IndexedSeq[ErgoBoxCandidate])

  object flattenedTxSerializer extends Serializer[FlattenedTransaction, FlattenedTransaction] {

    def bytesToSign(inputs: IndexedSeq[ADKey],
                    outputCandidates: IndexedSeq[ErgoBoxCandidate]): Array[Byte] = {
      //todo: set initial capacity
      val w = Serializer.startWriter()

      val inputsCount = inputs.size.toShort
      val outputsCount = outputCandidates.size.toShort

      w.putShort(inputsCount)
      inputs.foreach { i =>
        w.putBytes(i)
      }
      w.putShort(outputsCount)
      outputCandidates.foreach{ c =>
        w.putBytes(ErgoBoxCandidate.serializer.toBytes(c))
      }

      w.toBytes
    }

    def bytesToSign(tx: UnsignedErgoLikeTransaction): Array[Byte] =
      bytesToSign(tx.inputs.map(_.boxId), tx.outputCandidates)

    def bytesToSign(tx: ErgoLikeTransaction): Array[Byte] =
      bytesToSign(tx.inputs.map(_.boxId), tx.outputCandidates)


    override def toBytes(ftx: FlattenedTransaction): Array[Byte] = {
      ftx._1.map(_.spendingProof).foldLeft(bytesToSign(ftx._1.map(_.boxId), ftx._2)) { case (bytes, proof) =>
        bytes ++ ProverResult.serializer.toBytes(proof)
      }
    }

    override def parseBody(bytes: Array[Byte], pos: Position): (FlattenedTransaction, Consumed) = {
      val r = Serializer.startReader(bytes, pos)
      val inputsCount = r.getShort()

      val inputs = (0 until inputsCount).map { _ =>
        ADKey @@ r.getBytes(BoxId.size)
      }

      val outsCount = r.getShort()
      val outputs = (0 until outsCount).map { _ =>
        val (bc, cs) = ErgoBoxCandidate.serializer.parseBody(bytes, r.position)
        r.position_=(r.position + cs)
        bc
      }

      val proofs = (0 until inputsCount).map { _ =>
        val (pr, cs) = ProverResult.serializer.parseBody(bytes, r.position)
        r.position_=(r.position + cs)
        pr
      }

      val signedInputs = inputs.zip(proofs).map { case (inp, pr) =>
        Input(inp, pr)
      }

      (signedInputs, outputs) -> r.consumed
    }
  }

  object serializer extends Serializer[ErgoLikeTransaction, ErgoLikeTransaction] {
    override def toBytes(tx: ErgoLikeTransaction): Array[Byte] =
      flattenedTxSerializer.toBytes(tx.inputs, tx.outputCandidates)

    override def parseBody(bytes: Array[Byte], pos: Position): (ErgoLikeTransaction, Consumed) = {
      val ((inputs, outputCandidates), consumed) = flattenedTxSerializer.parseBody(bytes, pos)
      ErgoLikeTransaction(inputs, outputCandidates) -> consumed
    }
  }
}
