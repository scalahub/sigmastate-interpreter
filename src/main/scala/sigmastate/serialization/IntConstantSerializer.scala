package sigmastate.serialization

import com.google.common.primitives.Longs
import sigmastate.SInt
import sigmastate.SType.TypeCode
import sigmastate.Values._
import sigmastate.serialization.OpCodes._
import sigmastate.serialization.Serializer.Position


object IntConstantSerializer extends ValueSerializer[IntConstant] {
  override val opCode = IntConstantCode

  val typeCode: TypeCode = SInt.typeCode

  override def parseBody(bytes: Array[Byte], pos: Position) = {
    (IntConstant(Longs.fromByteArray(bytes.slice(pos, pos + 8))), 8)
  }

  override def serializeBody(c: IntConstant) = Longs.toByteArray(c.value)
}

