package sigmastate.serialization

import java.nio.ByteBuffer

import sigmastate.lang.exceptions.SerializerException
import sigmastate.serialization.Serializer.{Consumed, Position}
import sigmastate.utils._

import scala.util.Try

trait Serializer[TFamily, T <: TFamily] {

  final def toBytes(obj: T): Array[Byte] = serializeBody(obj)

  final def parseBytes(bytes: Array[Byte]): Try[TFamily] = Try {
    parseBody(bytes, 0)._1
  }

  final def parseBody(bytes: Array[Byte], pos: Position): (TFamily, Consumed) = {
    val r = Serializer.startReader(bytes, pos)
    parseBody(r) -> r.consumed
  }

  final def serializeBody(obj: T): Array[Byte] = {
    val w = Serializer.startWriter()
    serializeBody(obj, w)
    w.toBytes
  }

  def parseBody(r: ByteReader): TFamily
  def serializeBody(obj: T, w: ByteWriter): Unit

  def error(msg: String) = throw new SerializerException(msg, None)
}

object Serializer {
  type Position = Int
  type Consumed = Int

    /** Helper function to be use in serializers.
    * Starting position is marked and then used to compute number of consumed bytes.
    * val r = Serializer.startReader(bytes, pos)
    * val obj = r.getValue()
    * obj -> r.consumed */
  def startReader(bytes: Array[Byte], pos: Int): ByteReader = {
    val buf = ByteBuffer.wrap(bytes)
    buf.position(pos)
    val r = new ByteBufferReader(buf)
        .mark()
    r
  }

  /** Helper function to be use in serializers.
    * val w = Serializer.startWriter()
    * w.putLong(l)
    * val res = w.toBytes
    * res */
  def startWriter(): ByteWriter = {
    val b = new ByteArrayBuilder()
    val w = new ByteArrayWriter(b)
    w
  }
}

trait SigmaSerializer[TFamily, T <: TFamily] extends Serializer[TFamily, T] {
  val companion: SigmaSerializerCompanion[TFamily]
}

trait SigmaSerializerCompanion[TFamily] {
  type Tag
  val table: Map[Tag, SigmaSerializer[TFamily, _]]

  // todo make it final and wrap reader-based version
  def deserialize(bytes: Array[Byte], pos: Position): (TFamily, Consumed)
  def deserialize(r: ByteReader): TFamily

  // todo make it final and wrap writer-based version
  def serialize(v: TFamily): Array[Byte]
  def serialize(v: TFamily, w: ByteWriter): Unit
}

