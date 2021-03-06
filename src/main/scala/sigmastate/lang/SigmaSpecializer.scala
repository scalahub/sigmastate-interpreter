package sigmastate.lang

import org.bitbucket.inkytonik.kiama.rewriting.Rewriter.{reduce, rewrite, strategy}
import org.ergoplatform.ErgoBox
import sigmastate.SCollection.SByteArray
import sigmastate.Values.Value.Typed
import sigmastate.Values._
import sigmastate._
import sigmastate.lang.SigmaPredef._
import sigmastate.lang.Terms.{Apply, Block, Ident, Lambda, Select, Val, ValueOps}
import sigmastate.lang.exceptions.SpecializerException
import sigmastate.utxo._

class SigmaSpecializer(val builder: SigmaBuilder) {
  import SigmaSpecializer._
  import builder._

  /** Create name -> TaggedXXX(tag) pair to be used in environment. */
  def mkTagged(name: String, tpe: SType, tag: Byte): TaggedVariable[SType] = {
    val tagged = mkTaggedVariable(tag, tpe)
    tagged
  }

  /** Rewriting of AST with respect to environment to resolve all references
    * to let bound and lambda bound names. */
  private def eval(env: Map[String, SValue], e: SValue): SValue = rewrite(reduce(strategy[SValue]({
    case Ident(n, _) => env.get(n)

    case _ @ Block(binds, res) =>
      var curEnv = env
      for (Val(n, _, b) <- binds) {
        if (curEnv.contains(n)) error(s"Variable $n already defined ($n = ${curEnv(n)}")
        val b1 = eval(curEnv, b)
        curEnv = curEnv + (n -> b1)
      }
      val res1 = eval(curEnv, res)
      Some(res1)

    // Rule: allOf(arr) --> AND(arr)
    case Apply(AllSym, Seq(arr: Value[SCollection[SBoolean.type]]@unchecked)) =>
      Some(mkAND(arr))

    // Rule: anyOf(arr) --> OR(arr)
    case Apply(AnySym, Seq(arr: Value[SCollection[SBoolean.type]]@unchecked)) =>
      Some(mkOR(arr))

    // Rule: atLeast(bound, arr) --> AtLeast(bound, arr)
    case Apply(AtLeastSym, Seq(bound: SValue, arr: Value[SCollection[SBoolean.type]]@unchecked)) =>
      Some(mkAtLeast(bound.asIntValue, arr))

    case Apply(Blake2b256Sym, Seq(arg: Value[SByteArray]@unchecked)) =>
      Some(mkCalcBlake2b256(arg))

    case Apply(Sha256Sym, Seq(arg: Value[SByteArray]@unchecked)) =>
      Some(mkCalcSha256(arg))

    case Apply(IsMemberSym, Seq(tree: Value[SAvlTree.type]@unchecked, key: Value[SByteArray]@unchecked, proof: Value[SByteArray]@unchecked)) =>
      Some(mkIsMember(tree, key, proof))

    case Apply(TreeLookupSym, Seq(tree: Value[SAvlTree.type]@unchecked, key: Value[SByteArray]@unchecked, proof: Value[SByteArray]@unchecked)) =>
      Some(mkTreeLookup(tree, key, proof))

    case Apply(TreeModificationsSym, Seq(tree: Value[SAvlTree.type]@unchecked, operations: Value[SByteArray]@unchecked, proof: Value[SByteArray]@unchecked)) =>
      Some(mkTreeModifications(tree, operations, proof))

    case Apply(ProveDlogSym, Seq(g: Value[SGroupElement.type]@unchecked)) =>
      Some(mkProveDlog(g))

    case Apply(ProveDHTupleSym, Seq(g, h, u, v)) =>
      Some(mkProveDiffieHellmanTuple(g.asGroupElement, h.asGroupElement, u.asGroupElement, v.asGroupElement))

    case Apply(LongToByteArraySym, Seq(arg: Value[SLong.type]@unchecked)) =>
      Some(mkLongToByteArray(arg))

    case Apply(FromBase58Sym, Seq(arg: Value[SString.type]@unchecked)) =>
      Some(mkBase58ToByteArray(arg))

    case Apply(FromBase64Sym, Seq(arg: Value[SString.type]@unchecked)) =>
      Some(mkBase64ToByteArray(arg))

    case Apply(ByteArrayToBigIntSym, Seq(arg: Value[SByteArray]@unchecked)) =>
      Some(mkByteArrayToBigInt(arg))

    case Upcast(Constant(value, tpe), toTpe: SNumericType) =>
      Some(mkConstant(toTpe.upcast(value.asInstanceOf[AnyVal]), toTpe))

    case Downcast(Constant(value, tpe), toTpe: SNumericType) =>
      Some(mkConstant(toTpe.downcast(value.asInstanceOf[AnyVal]), toTpe))

    // Rule: numeric.to* casts
    case Select(obj, method, Some(tRes: SNumericType))
      if obj.tpe.isNumType && obj.asNumValue.tpe.isCastMethod(method) =>
      val numValue = obj.asNumValue
      if (numValue.tpe == tRes)
        Some(numValue)
      else if ((numValue.tpe max tRes) == numValue.tpe)
        Some(mkDowncast(numValue, tRes))
      else
        Some(mkUpcast(numValue, tRes))

    // Rule: col.size --> SizeOf(col)
    case Select(obj, "size", _) =>
      if (obj.tpe.isCollectionLike)
        Some(mkSizeOf(obj.asValue[SCollection[SType]]))
      else
        error(s"The type of $obj is expected to be Collection to select 'size' property")

    // Rule: proof.isValid --> IsValid(proof)
    case Select(p, SSigmaProp.IsValid, _) if p.tpe == SSigmaProp =>
      Some(SigmaPropIsValid(p.asSigmaProp))

    // Rule: proof.propBytes --> ProofBytes(proof)
    case Select(p, SSigmaProp.PropBytes, _) if p.tpe == SSigmaProp =>
      Some(SigmaPropBytes(p.asSigmaProp))

    case Apply(PKSym, Seq(arg: Value[SString.type]@unchecked)) =>
      Some(mkPK(arg))

    case sel @ Select(Typed(box, SBox), regName, Some(SOption(valType))) if regName.startsWith("R") =>
      val reg = ErgoBox.registerByName.getOrElse(regName,
        error(s"Invalid register name $regName in expression $sel"))
      Some(mkExtractRegisterAs(box.asBox, reg, SOption(valType)).asValue[SOption[valType.type]])

    case Select(nrv: NotReadyValue[SOption[SType]]@unchecked, SOption.Get, _) =>
      Some(mkOptionGet(nrv))

    case Apply(Select(nrv: NotReadyValue[SOption[SType]]@unchecked, SOption.GetOrElse, _), Seq(arg)) =>
      Some(mkOptionGetOrElse(nrv, arg))

    case Select(nrv: NotReadyValue[SOption[SType]]@unchecked, SOption.IsDefined, _) =>
      Some(mkOptionIsDefined(nrv))

    case sel @ Select(obj, field, _) if obj.tpe == SBox =>
      (obj.asValue[SBox.type], field) match {
        case (box, SBox.Value) => Some(mkExtractAmount(box))
        case (box, SBox.PropositionBytes) => Some(mkExtractScriptBytes(box))
        case (box, SBox.Id) => Some(mkExtractId(box))
        case (box, SBox.Bytes) => Some(mkExtractBytes(box))
        case (box, SBox.BytesWithNoRef) => Some(mkExtractBytesWithNoRef(box))
        case (box, SBox.CreationInfo) => Some(mkExtractCreationInfo(box))
        case (box, _) if box.tpe.hasMethod(field) =>
          None  // leave it as it is and handle on a level of parent node
        case _ => error(s"Invalid access to Box property in $sel: field $field is not found")
      }

    case Select(obj: SigmaBoolean, field, _) =>
      field match {
        case SigmaBoolean.PropBytes => Some(ByteArrayConstant(obj.bytes))
        case SigmaBoolean.IsValid => Some(obj)
      }

    case Select(tuple, fn, _) if tuple.tpe.isTuple && fn.startsWith("_") =>
      val index = fn.substring(1).toByte
      Some(mkSelectField(tuple.asTuple, index))

    case Apply(Select(col, "slice", _), Seq(from, until)) =>
      Some(mkSlice(col.asValue[SCollection[SType]], from.asIntValue, until.asIntValue))

    case Apply(Select(col, "where", _), Seq(Lambda(_, Seq((n, t)), _, Some(body)))) =>
      val tagged = mkTagged(n, t, 21)
      val body1 = eval(env + (n -> tagged), body)
      Some(mkWhere(col.asValue[SCollection[SType]], tagged.varId, body1.asValue[SBoolean.type]))

    case Apply(Select(col,"exists", _), Seq(Lambda(_, Seq((n, t)), _, Some(body)))) =>
      val tagged = mkTagged(n, t, 21)
      val body1 = eval(env + (n -> tagged), body)
      Some(mkExists(col.asValue[SCollection[SType]], tagged.varId, body1.asValue[SBoolean.type]))

    case Apply(Select(col,"forall", _), Seq(Lambda(_, Seq((n, t)), _, Some(body)))) =>
      val tagged = mkTagged(n, t, 21)
      val body1 = eval(env + (n -> tagged), body)
      Some(mkForAll(col.asValue[SCollection[SType]], tagged.varId, body1.asValue[SBoolean.type]))

    case Apply(Select(col,"map", _), Seq(Lambda(_, Seq((n, t)), _, Some(body)))) =>
      val tagged = mkTagged(n, t, 21)
      val body1 = eval(env + (n -> tagged), body)
      Some(mkMapCollection(col.asValue[SCollection[SType]], tagged.varId, body1))

    case Apply(Select(col,"fold", _), Seq(zero, Lambda(_, Seq((accArg, tAccArg), (opArg, tOpArg)), _, Some(body)))) =>
      val taggedAcc = mkTagged(accArg, tAccArg, 21)
      val taggedOp = mkTagged(opArg, tOpArg, 22)
      val body1 = eval(env ++ Seq(accArg -> taggedAcc, opArg -> taggedOp), body)
      Some(mkFold(col.asValue[SCollection[SType]], taggedOp.varId, zero, taggedAcc.varId, body1))

    case Apply(Select(col,"getOrElse", _), Seq(index, defaultValue)) =>
      val index1 = eval(env, index).asValue[SInt.type]
      val defaultValue1 = eval(env, defaultValue).asValue[SType]
      Some(mkByIndex(col.asValue[SCollection[SType]], index1, Some(defaultValue1)))

    case Apply(col, Seq(index)) if col.tpe.isCollection =>
      Some(ByIndex(col.asCollection[SType], index.asValue[SInt.type]))

    case opt: OptionValue[_] =>
      error(s"Option constructors are not supported: $opt")

    case AND(ConcreteCollection(items, SBoolean)) if items.exists(_.isInstanceOf[AND]) =>
      Some(mkAND(
        mkConcreteCollection(
          items.flatMap {
            case AND(ConcreteCollection(innerItems, SBoolean)) => innerItems
            case v => IndexedSeq(v)
          }, SBoolean)))

    case OR(ConcreteCollection(items, SBoolean)) if items.exists(_.isInstanceOf[OR]) =>
      Some(mkOR(
        mkConcreteCollection(
          items.flatMap {
            case OR(ConcreteCollection(innerItems, SBoolean)) => innerItems
            case v => IndexedSeq(v)
          }, SBoolean)))

  })))(e)

  def specialize(typed: SValue): SValue = {
    specialize(Map(), typed)
  }

  def specialize(env: Map[String, SValue], typed: SValue): SValue = {
    val res = eval(env, typed)
    res
  }
}

object SigmaSpecializer {
  def error(msg: String) = throw new SpecializerException(msg, None)
}
