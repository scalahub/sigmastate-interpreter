package sigmastate.utxo.examples

import org.ergoplatform.{ErgoLikeContext, Height}
import scorex.crypto.hash.Blake2b256
import scorex.utils.Random
import sigmastate.Values._
import sigmastate._
import sigmastate.helpers.{ErgoLikeTestProvingInterpreter, SigmaTestingCommons}
import sigmastate.lang.Terms._
import sigmastate.utxo.{ErgoLikeTestInterpreter, SizeOf}

class AtomicSwapExampleSpecification extends SigmaTestingCommons {

  /**
    * Atomic cross-chain trading example:
    * Alice(A) has coins in chain 1, Bob(B) has coins in chain 2, they want to exchange them atomically and with no
    * any trusted mediate.
    *
    * Alternative protocol for Bitcoin is described in this forum message,
    * https://bitcointalk.org/index.php?topic=193281.msg2224949#msg2224949,
    * this implementation is simpler. In particular, only one transaction(one output) is required per party.
    */
  property("atomic cross-chain trading") {
    val x = Random.randomBytes(32)
    val proverA = (new ErgoLikeTestProvingInterpreter).withContextExtender(1, ByteArrayConstant(x))
    val proverB = new ErgoLikeTestProvingInterpreter
    val pubkeyA = proverA.dlogSecrets.head.publicImage
    val pubkeyB = proverB.dlogSecrets.head.publicImage
    val verifier = new ErgoLikeTestInterpreter

    val hx = ByteArrayConstant(Blake2b256(x))

    val height1 = 100000L
    val height2 = 50000L

    val deadlineA = 1000L
    val deadlineB = 500L

    val env = Map(
      "height1" -> height1, "height2" -> height2,
      "deadlineA" -> deadlineA, "deadlineB" -> deadlineB,
      "pubkeyA" -> pubkeyA, "pubkeyB" -> pubkeyB, "hx" -> hx)
    val prop1 = compile(env,
      """{
        |  anyOf(Array(
        |    HEIGHT > height1 + deadlineA && pubkeyA,
        |    pubkeyB && blake2b256(getVar[Array[Byte]](1).get) == hx
        |  ))
        |}""".stripMargin).asBoolValue

    //chain1 script
    val prop1Tree = OR(
      AND(GT(Height, Plus(LongConstant(height1), LongConstant(deadlineA))), pubkeyA),
      AND(pubkeyB, EQ(CalcBlake2b256(GetVarByteArray(1).get), hx))
    )
    prop1 shouldBe prop1Tree

    val script2 =
      """{
        |  anyOf(Array(
        |    HEIGHT > height2 + deadlineB && pubkeyB,
        |    allOf(Array(
        |        pubkeyA,
        |        getVar[Array[Byte]](1).get.size<33,
        |        blake2b256(getVar[Array[Byte]](1).get) == hx
        |    ))
        |  ))
        |}
      """.stripMargin
    val prop2 = compile(env, script2).asBoolValue

    //chain2 script
    val prop2Tree = OR(
      AND(GT(Height, Plus(LongConstant(height2), LongConstant(deadlineB))), pubkeyB),
      AND(pubkeyA,
        LT(SizeOf(GetVarByteArray(1).get), 33),
        EQ(CalcBlake2b256(GetVarByteArray(1).get), hx))
    )
    prop2 shouldBe prop2Tree


    //Preliminary checks:

    //B can't spend coins of A in chain1 (generate a valid proof)
    val ctxf1 = ErgoLikeContext(
      currentHeight = height1 + 1,
      lastBlockUtxoRoot = AvlTreeData.dummy,
      minerPubkey = ErgoLikeContext.dummyPubkey,
      boxesToSpend = IndexedSeq(),
      spendingTransaction = null,
      self = fakeSelf)
    proverB.prove(prop1, ctxf1, fakeMessage).isSuccess shouldBe false

    //A can't withdraw her coins in chain1 (generate a valid proof)
    proverA.prove(prop1, ctxf1, fakeMessage).isSuccess shouldBe false

    //B cant't withdraw his coins in chain2 (generate a valid proof)
    val ctxf2 = ErgoLikeContext(
      currentHeight = height2 + 1,
      lastBlockUtxoRoot = AvlTreeData.dummy,
      minerPubkey = ErgoLikeContext.dummyPubkey,
      boxesToSpend = IndexedSeq(), spendingTransaction = null, self = fakeSelf)
    proverB.prove(prop2, ctxf2, fakeMessage).isSuccess shouldBe false

    //Successful run below:

    //A spends coins of B in chain2
    val ctx1 = ErgoLikeContext(
      currentHeight = height2 + 1,
      lastBlockUtxoRoot = AvlTreeData.dummy,
      minerPubkey = ErgoLikeContext.dummyPubkey,
      boxesToSpend = IndexedSeq(),
      spendingTransaction = null,
      self = fakeSelf)
    val pr = proverA.prove(prop2, ctx1, fakeMessage).get
    verifier.verify(prop2, ctx1, pr, fakeMessage).get._1 shouldBe true

    //B extracts preimage x of hx
    val t = pr.extension.values(1)
    val proverB2 = proverB.withContextExtender(1, t.asInstanceOf[CollectionConstant[SByte.type]])

    //B spends coins of A in chain1 with knowledge of x
    val ctx2 = ErgoLikeContext(
      currentHeight = height1 + 1,
      lastBlockUtxoRoot = AvlTreeData.dummy,
      minerPubkey = ErgoLikeContext.dummyPubkey,
      boxesToSpend = IndexedSeq(),
      spendingTransaction = null,
      self = fakeSelf)
    val pr2 = proverB2.prove(prop1, ctx2, fakeMessage).get
    verifier.verify(prop1, ctx2, pr2, fakeMessage).get._1 shouldBe true

    // Bad prover with x that is too long should fail
    // Replace x with a longer one and hx with the hash of this longer x in the script
    // and check that the A fails to prove
    val badX = Random.randomBytes(33)
    val badProverA = proverA.withContextExtender(1, ByteArrayConstant(badX))
    val badHx = ByteArrayConstant(Blake2b256(badX))
    val badEnv = env + ("hx" -> badHx)
    val badProp2 = compile(badEnv, script2).asBoolValue

    badProverA.prove(badProp2, ctx1, fakeMessage).isSuccess shouldBe false
  }
}