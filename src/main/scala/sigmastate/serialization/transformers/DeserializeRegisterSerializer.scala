package sigmastate.serialization.transformers

import org.ergoplatform.ErgoBox
import org.ergoplatform.ErgoBox.RegisterId
import sigmastate.SType
import sigmastate.Values.Value
import sigmastate.serialization.OpCodes.OpCode
import sigmastate.serialization.{OpCodes, ValueSerializer}
import sigmastate.utils.Extensions._
import sigmastate.utils.{ByteReader, ByteWriter}
import sigmastate.utxo.DeserializeRegister

case class DeserializeRegisterSerializer(cons: (RegisterId, SType, Option[Value[SType]]) => Value[SType])
  extends ValueSerializer[DeserializeRegister[SType]] {

  override val opCode: OpCode = OpCodes.DeserializeRegisterCode

  override def serializeBody(obj: DeserializeRegister[SType], w: ByteWriter): Unit =
    w.put(obj.reg.number)
      .putType(obj.tpe)
      .putOption(obj.default)(_.putValue(_))

  override def parseBody(r: ByteReader): Value[SType] = {
    val registerId = ErgoBox.findRegisterByIndex(r.getByte()).get
    val tpe = r.getType()
    val dv = r.getOption(r.getValue())
    cons(registerId, tpe, dv)
  }

}
