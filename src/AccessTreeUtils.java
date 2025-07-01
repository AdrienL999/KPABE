import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.Integer.valueOf;

public class AccessTreeUtils {

    public static Element[] randomP(int d, Element s, Pairing bp){
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].duplicate();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (j != i) {
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                Element term = numerator.div(denominator);
                res = res.mul(term);
            }
        }
        return res;
    }

    public static void nodeShare(Node[] nodes, Node n, Pairing bp) {
        if (!n.isLeaf()) {
            Element[] coef = randomP(n.gate[0], n.sharesecret, bp);
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                childNode.sharesecret = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    public static boolean nodeRecover(Node[] nodes, Node n, String[] atts, Pairing bp, boolean isGTMode) {
        if (!n.isLeaf()) {
            List<Integer> validChildrenList = new ArrayList<>();
            for (int i = 0; i < n.children.length; i++) {
                Node childNode = nodes[n.children[i]];
                if (nodeRecover(nodes, childNode, atts, bp, true)) {
                    validChildrenList.add(valueOf(n.children[i]));
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
            }

            if (validChildrenList.size() == n.gate[0]) {
                int[] validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                Element secret = isGTMode ? bp.getGT().newOneElement().getImmutable()
                        : bp.getZr().newZeroElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);
                    if (isGTMode) {
                        secret = secret.mul(nodes[i].sharesecret.duplicate().powZn(delta)); // GT *
                    } else {
                        secret = secret.add(nodes[i].sharesecret.duplicate().mul(delta));    // Zr +
                    }
                }
                n.sharesecret = secret;
            }
        } else {
            boolean matched = Arrays.stream(atts)
                    .map(String::trim)
                    .anyMatch(attr -> attr.equals(n.att.trim()));
            if (matched) {
                n.valid = true;
                System.out.printf("✅ 属性匹配成功: %s\n", n.att);
            } else {
                System.out.printf("❌ 属性匹配失败: %s （不在属性集合 %s 中）\n", n.att, Arrays.toString(atts));
            }
        }
        return n.valid;
    }
}
