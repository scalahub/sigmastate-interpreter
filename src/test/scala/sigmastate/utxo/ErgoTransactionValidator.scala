package sigmastate.utxo

import org.ergoplatform.ErgoLikeContext.Metadata
import org.ergoplatform._

import scala.util.{Failure, Success}

class ErgoLikeTestInterpreter(override val maxCost: Long = CostTable.ScriptLimit) extends ErgoLikeInterpreter(maxCost) {
  override type CTX = ErgoLikeContext
}


object ErgoTransactionValidator {
  val verifier: ErgoLikeTestInterpreter = new ErgoLikeTestInterpreter()

  //todo: check that outputs are well-formed?
  def validate(tx: ErgoLikeTransaction,
               blockchainState: BlockchainState,
               minerPubkey: Array[Byte],
               boxesReader: ErgoBoxReader,
               metadata: Metadata): Either[Throwable, Long] = {

    val msg = tx.messageToSign
    val inputs = tx.inputs

    val boxes: IndexedSeq[ErgoBox] = tx.inputs.map(_.boxId).map{id =>
      boxesReader.byId(id) match {
        case Success(box) => box
        case Failure(e) => return Left[Throwable, Long](e)
      }
    }

    val txCost = boxes.zipWithIndex.foldLeft(0L) { case (accCost, (box, idx)) =>
      val input = inputs(idx)
      val proof = input.spendingProof

      val proverExtension = tx.inputs(idx).spendingProof.extension

      val context =
        ErgoLikeContext(blockchainState.currentHeight, blockchainState.lastBlockUtxoRoot, minerPubkey, boxes,
          tx, box, metadata, proverExtension)

      val scriptCost: Long = verifier.verify(box.proposition, context, proof, msg) match {
        case Success((res, cost)) =>
          if(!res) return Left[Throwable, Long](new Exception(s"Validation failed for input #$idx"))
          else cost
        case Failure(e) =>
          return Left[Throwable, Long](e)
      }
      accCost + scriptCost
    }
    Right(txCost)
  }
}