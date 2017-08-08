package sigmastate.utxo

import sigmastate._
import org.bitbucket.inkytonik.kiama.rewriting.Rewriter._
import org.bitbucket.inkytonik.kiama.rewriting.Strategy
import sigmastate.interpreter.Interpreter

import scala.collection.mutable


class UtxoInterpreter(override val maxCost: Int = CostTable.ScriptLimit) extends Interpreter {
  override type StateT = StateTree
  override type CTX = UtxoContext

  private def replaceTxOut(idxOut: TxOutput, context: UtxoContext): AND = {
    val ts = idxOut.relation.map { rel =>
      (rel.left, rel.right) match {
        case (OutputAmount, _) | (_, OutputAmount) => OutputAmount -> rel
        case (OutputScript, _) | (_, OutputScript) => OutputScript -> rel
        case _ => ???
      }
    }

    val out = context.spendingTransaction.newBoxes(idxOut.outIndex)
    val amount = out.value
    val bindings = mutable.Map[Variable[_], Value]()

    val relations = ts.map { case (v, r) =>
      v match {
        case OutputAmount =>
          bindings.put(OutputAmount, IntLeaf(amount))
          r
        case OutputScript =>
          bindings.put(OutputScript, PropLeaf(out.proposition))
          r
        case _ => ???
      }
    }
    val rels = relations.map { r =>
      val rl = r.left match {
        case v: Variable[_] =>
          bindings.get(v) match {
            case Some(value) => r.withLeft(value)
            case None => r
          }
        case _ => r
      }

      rl.right match {
        case v: Variable[_] =>
          bindings.get(v) match {
            case Some(value) => rl.withRight(value)
            case None => rl
          }
        case _ => rl
      }
    }
    println("rels: " + rels)
    AND(rels)
  }

  def ssSubst(context: UtxoContext, cost: CostAccumulator): Strategy = everywherebu(rule[SigmaStateTree] {
    case SelfScript =>
      val leaf = PropLeaf(context.self._1.proposition)
      cost.addCost(leaf.cost).ensuring(_.isRight)
      leaf

    case hasOut: TxHasOutput =>
      val s = context.spendingTransaction.newBoxes.size
      val outConditions = (0 until s).map { idx =>
        val out = TxOutput(idx, hasOut.relation:_*)
        val and = replaceTxOut(out, context)
        cost.addCost(and.cost).ensuring(_.isRight)
        and
      }
      cost.addCost(outConditions.length).ensuring(_.isRight)
      OR(outConditions)

    case idxOut: TxOutput => replaceTxOut(idxOut, context)
  })

  def varSubst(context: UtxoContext): Strategy = everywherebu(
    rule[Value] {
      case Height => IntLeaf(context.currentHeight)
      case SelfHeight => IntLeaf(context.self._2)
      case SelfAmount => IntLeaf(context.self._1.value)
    })

  override def specificPhases(tree: SigmaStateTree, context: UtxoContext, cost: CostAccumulator): SigmaStateTree = {
    val afterSs = ssSubst(context, cost)(tree).get.asInstanceOf[SigmaStateTree]
    varSubst(context)(afterSs).get.asInstanceOf[SigmaStateTree]
  }
}
