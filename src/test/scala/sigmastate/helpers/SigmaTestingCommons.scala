package sigmastate.helpers

import org.ergoplatform.ErgoBox
import org.ergoplatform.ErgoBox.{NonMandatoryRegisterId, TokenId}
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.hash.Blake2b256
import scorex.util._
import sigmastate.Values.{EvaluatedValue, GroupElementConstant, TrueLeaf, Value}
import sigmastate.interpreter.CryptoConstants
import sigmastate.lang.SigmaCompiler
import sigmastate.{SBoolean, SGroupElement, SType}

import scala.language.implicitConversions

trait SigmaTestingCommons extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {


  val fakeSelf: ErgoBox = createBox(0, TrueLeaf)

  //fake message, in a real-life a message is to be derived from a spending transaction
  val fakeMessage = Blake2b256("Hello World")

  implicit def grElemConvert(leafConstant: GroupElementConstant): CryptoConstants.EcPointType = leafConstant.value

  implicit def grLeafConvert(elem: CryptoConstants.EcPointType): Value[SGroupElement.type] = GroupElementConstant(elem)

  val compiler = new SigmaCompiler

  def compile(env: Map[String, Any], code: String): Value[SType] = {
    compiler.compile(env, code)
  }

  def createBox(value: Int,
                proposition: Value[SBoolean.type],
                additionalTokens: Seq[(TokenId, Long)] = Seq(),
                additionalRegisters: Map[NonMandatoryRegisterId, _ <: EvaluatedValue[_ <: SType]] = Map())
    = ErgoBox(value, proposition, additionalTokens, additionalRegisters)

  def createBox(value: Int,
                proposition: Value[SBoolean.type],
                creationHeight: Long)
    = ErgoBox(value, proposition, Seq(), Map(), Array.fill[Byte](32)(0.toByte).toModifierId, 0, creationHeight)
}
