import it.unisa.dia.gas.jpbc.Element;

import java.util.*;

public class KPABEPerformanceTest {

    public static void main(String[] args) {
        runDynamicTest(
                10,    // 起始属性数
                10,    // 每轮增加属性数量
                100,   // 最大属性数
                5,     // 每组属性测试轮数
                0.3    // 密文属性占属性全集比例（30%）
        );
    }

    public static void runDynamicTest(int startAttrCount, int step, int maxAttrCount, int testRounds, double messageAttrRatio) {
        String pairingParamsFileName = "a.properties";

        for (int attrCount = startAttrCount; attrCount <= maxAttrCount; attrCount += step) {
            System.out.printf("===== 属性全集大小: %d =====\n", attrCount);

            String[] U = generateAttributeUniverse(attrCount);
            long totalSetup = 0, totalKeygen = 0, totalEnc = 0, totalDec = 0;

            for (int round = 0; round < testRounds; round++) {
                System.out.printf("---- 测试轮 %d/%d ----\n", round + 1, testRounds);

                String[] messageAttList = pickRandomAttributes(U, (int) (attrCount * messageAttrRatio));
                Node[] tree = buildRandomAccessTree(messageAttList);

                String pk = "data/pk_" + attrCount + "_" + round + ".properties";
                String msk = "data/msk_" + attrCount + "_" + round + ".properties";
                String sk = "data/sk_" + attrCount + "_" + round + ".properties";
                String ct = "data/ct_" + attrCount + "_" + round + ".properties";

                long t1 = System.currentTimeMillis();
                KPABE.setup(pairingParamsFileName, U, pk, msk);
                long t2 = System.currentTimeMillis();
                KPABE.keygen(pairingParamsFileName, tree, pk, msk, sk);
                long t3 = System.currentTimeMillis();

                Element message = KPABE.getPairing(pairingParamsFileName).getGT().newRandomElement().getImmutable();

                KPABE.encrypt(pairingParamsFileName, message, messageAttList, pk, ct);
                long t4 = System.currentTimeMillis();

                for (Node node : tree) node.sharesecret = null;

                Element decrypted = KPABE.decrypt(pairingParamsFileName, tree, pk, ct, sk);
                long t5 = System.currentTimeMillis();

                totalSetup += (t2 - t1);
                totalKeygen += (t3 - t2);
                totalEnc += (t4 - t3);
                totalDec += (t5 - t4);

                boolean success = message.equals(decrypted);
                System.out.println("解密" + (success ? "成功 ✅" : "失败 ❌"));
            }

            System.out.printf("== 平均性能：属性全集大小 = %d ==\n", attrCount);
            System.out.printf("Setup   平均时间: %.2f ms\n", totalSetup / (double) testRounds);
            System.out.printf("KeyGen  平均时间: %.2f ms\n", totalKeygen / (double) testRounds);
            System.out.printf("Encrypt 平均时间: %.2f ms\n", totalEnc / (double) testRounds);
            System.out.printf("Decrypt 平均时间: %.2f ms\n", totalDec / (double) testRounds);
            System.out.println();
        }
    }

    // 动态构造属性全集
    public static String[] generateAttributeUniverse(int count) {
        String[] U = new String[count];
        for (int i = 0; i < count; i++) {
            char letter = (char) ('A' + i / 10);
            int number = i % 10 + 1;
            U[i] = String.format("%c%d", letter, number);
        }
        return U;
    }

    // 从全集中随机抽取密文属性
    public static String[] pickRandomAttributes(String[] U, int count) {
        List<String> list = new ArrayList<>(Arrays.asList(U));
        Collections.shuffle(list);
        return list.subList(0, Math.min(count, list.size())).toArray(new String[0]);
    }

    // 自动构造一个简单的 2 层访问树
    public static Node[] buildRandomAccessTree(String[] messageAttList) {
        int leafCount = Math.min(5, messageAttList.length); // 控制叶子节点数量

        Node[] tree = new Node[1 + leafCount];
        int[] childIndices = new int[leafCount];
        for (int i = 0; i < leafCount; i++) {
            tree[i + 1] = new Node(messageAttList[i]); // 叶子节点
            childIndices[i] = i + 1;
        }
        // 根节点为 k of n 门限结构
        int threshold = Math.max(2, leafCount / 2);
        tree[0] = new Node(new int[]{threshold, leafCount}, childIndices);
        return tree;
    }
}
