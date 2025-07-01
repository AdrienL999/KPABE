import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;
import java.util.logging.Level;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;

import static java.lang.Integer.valueOf;

public class KPABE {
    private static final Logger logger = Logger.getLogger(KPABE.class.getName());

    static {
        try {
            // 1. 创建 logs 目录（如果不存在）
            java.nio.file.Path logDir = java.nio.file.Paths.get("logs");
            if (!java.nio.file.Files.exists(logDir)) {
                java.nio.file.Files.createDirectories(logDir);
                System.out.println("✅ 已自动创建日志目录：logs/");
            }

            // 2. 创建日志文件处理器
            FileHandler fh = new FileHandler("logs/kpabe.log", true); // true 表示追加写入
            fh.setFormatter(new SimpleFormatter());

            logger.addHandler(fh);
            logger.setUseParentHandlers(false); // 不再打印到控制台（如需打印，注释此行）

        } catch (Exception e) {
            System.err.println("⚠️ 无法初始化日志文件: " + e.getMessage());
        }
    }

    private static Pairing pairing;

    public static Pairing getPairing(String pairingParamsFileName){
        if(pairing == null){
            pairing = PairingFactory.getPairing(pairingParamsFileName);
        }
        return pairing;
    }

    public static void resetPairing() {
        pairing = null;
    }

    public static void setup(String pairingParamsFileName, String[] U, String pkFileName, String mskFileName) {
        Pairing bp = getPairing(pairingParamsFileName); // ✅ 使用统一的共享 pairing 实例

        Element g = bp.getG1().newRandomElement().getImmutable();
        Properties pkProperties = new Properties();
        Properties mskProperties = new Properties();

        IntStream.rangeClosed(0, U.length - 1).parallel().forEach(i -> {
            Element t = bp.getZr().newRandomElement().getImmutable();
            Element T = g.duplicate().powZn(t);
            synchronized (mskProperties) {
                mskProperties.setProperty("t" + U[i], Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
            }
            synchronized (pkProperties) {
                pkProperties.setProperty("T" + U[i], Base64.getEncoder().withoutPadding().encodeToString(T.toBytes()));
            }
        });

//        for(int i = 0; i < U; i++){
//            Element t = bp.getZr().newRandomElement().getImmutable();
//            Element T = g.duplicate().powZn(t);
//            mskProperties.setProperty("t"+i, Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
//            pkProperties.setProperty("T"+i, Base64.getEncoder().withoutPadding().encodeToString(T.toBytes()));
//        }
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element Y = bp.pairing(g,g).powZn(y).getImmutable();
        synchronized (mskProperties) {
            mskProperties.setProperty("y", Base64.getEncoder().withoutPadding().encodeToString(y.toBytes()));
        }
        synchronized (pkProperties) {
            pkProperties.setProperty("Y", Base64.getEncoder().withoutPadding().encodeToString(Y.toBytes()));
            pkProperties.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        }

        storePropToFile(pkProperties, pkFileName);
        storePropToFile(mskProperties, mskFileName);
    }

    public static void keygen(String pairingParamsFileName, Node[] accessTree, String pkFileName, String mskFileName, String skFileName) {
        Pairing bp = getPairing(pairingParamsFileName);

        Properties pkProperties = loadPropFromFile(pkFileName);
        String gString = pkProperties.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Properties mskProperties = loadPropFromFile(mskFileName);
        String yString = mskProperties.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yString)).getImmutable();

        accessTree[0].sharesecret = y;//先设置根节点要共享的秘密值
        AccessTreeUtils.nodeShare(accessTree, accessTree[0], bp);

        Properties skProperties = new Properties();
        for(Node node : accessTree){
            if(node.isLeaf()){
                String tString = mskProperties.getProperty("t"+node.att);
                Element t = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
                Element q = node.sharesecret;
                Element D = g.powZn(q.div(t)).getImmutable();
                skProperties.setProperty("D"+node.att, Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
            }
        }
        storePropToFile(skProperties, skFileName);
    }

    public static void encrypt(String pairingParamsFileName, Element message, String[] messageAttList, String pkFileName, String ctFileName) {
        Pairing bp = getPairing(pairingParamsFileName);//初始化双线性对
        Properties pkProperties = loadPropFromFile(pkFileName);
        String YString = pkProperties.getProperty("Y");//加载公钥
        Element Y = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(YString)).getImmutable();

        Element s = bp.getZr().newRandomElement().getImmutable();
        Element E1 = message.duplicate().mul(Y.powZn(s)).getImmutable();//计算第一个密文组件，就是E'

        Properties ctProperties = new Properties();
        for (String att: messageAttList){//遍历所有属性，计算每个属性对应的E2组件，其实就是Ei
            String TString = pkProperties.getProperty("T" + att);
            Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();
            Element E2 = T.powZn(s).getImmutable();

            ctProperties.setProperty("E2"+att, Base64.getEncoder().withoutPadding().encodeToString(E2.toBytes()));
        }

        ctProperties.setProperty("E1", Base64.getEncoder().withoutPadding().encodeToString(E1.toBytes()));
        // 修改encrypt方法中保存属性列表的方式
        ctProperties.setProperty("messageAttList", Arrays.toString(messageAttList));
        storePropToFile(ctProperties, ctFileName);
    }

    public static Element decrypt(String pairingParamsFileName, Node[] accessTree, String pkFileName, String ctFileName, String skFileName){
        Pairing bp = getPairing(pairingParamsFileName);
        Properties pkProperties = loadPropFromFile(pkFileName);
        Properties ctProperties = loadPropFromFile(ctFileName);
        String messageAttListString = ctProperties.getProperty("messageAttList");
        // // 修复1：正确解析属性列表（去掉可能的方括号）
        // 将格式如 "[A1, B2, C3]" 的字符串转换为纯净的字符串数组 ["A1", "B2", "C3"]。
        String[] messageAttList = messageAttListString.replace("[", "").replace("]", "")
                .replace(" ", "").split(",");


        Properties skProperties = loadPropFromFile(skFileName);
        for(Node node : accessTree){
            if(node.isLeaf()){
//                if (Arrays.stream(messageAttList)
//                        .boxed()
//                        .collect(Collectors.toList())
//                        .contains(node.att)){
                if(Arrays.asList(messageAttList).contains(node.att.trim())){// 修复2：添加trim()处理空格
                    String E2String = ctProperties.getProperty("E2"+node.att.trim());
                    if(E2String == null) {
                        System.err.println("❌ 密文中缺少属性" + node.att + "对应的E2值");
                        continue;
                    }
                    Element E2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E2String)).getImmutable();
                    String DString = skProperties.getProperty("D"+node.att.trim());
                    if(DString == null) {
                        System.err.println("❌ 私钥中缺少属性" + node.att + "对应的D值");
                        continue;
                    }
                    Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
                    node.sharesecret = bp.pairing(E2, D).getImmutable();
                }
            }
        }

        boolean treeOK = AccessTreeUtils.nodeRecover(accessTree, accessTree[0], messageAttList, bp, true);
        if(treeOK){
            String E1String = ctProperties.getProperty("E1");
            if(E1String == null) {
                System.err.println("❌ 密文中缺少E1值");
                return null;
            }
            Element E1 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(E1String)).getImmutable();
            Element res = E1.div(accessTree[0].sharesecret);
            return res;
        }
        else{
            System.out.println("❌ 访问树不满足！");
            return null;
        }

    }

//    public static void storePropToFile(Properties prop, String fileName) {
//        try{
//            Path path = Paths.get(fileName);
//            Path parentDir = path.getParent();
//            if(parentDir != null && Files.exists(parentDir)){
//                Files.createDirectories(parentDir);
//                System.out.println("✅创建目录：" + parentDir);
//            }
//            try(OutputStream outputStream = Files.newOutputStream(path)){
//                prop.store(outputStream, "System Parameters");
//            }
//        } catch (IOException e) {
//            System.err.println("保存失败" + fileName);
//            System.err.println("错误详情：" + e.getMessage());
//            throw new RuntimeException(e);
//        }
//    }

    public static void storePropToFile(Properties prop, String fileName) {
        try {
            Path path = Paths.get(fileName);
            Path parentDir = path.getParent();

            // 确保父目录存在
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
                System.out.println("✅ 创建目录：" + parentDir);
            }

            try (OutputStream outputStream = Files.newOutputStream(path)) {
                prop.store(outputStream, "System Parameters");
                logger.info("✅ 文件保存成功: " + path.toAbsolutePath());//日志就会写入 logs/kpabe.log 文件，不再输出到控制台
//                System.out.println("✅ 文件保存成功：" + path); // 添加成功确认
            }
        } catch (IOException e) {
            System.err.println("❌ 保存失败：" + fileName);
            throw new RuntimeException("保存失败: " + e.getMessage(), e);
        }
    }


    public static Properties loadPropFromFile(String fileName) {
        if(!Files.exists(Paths.get(fileName))){
            throw new IllegalArgumentException("文件不存在" + fileName);
        }
        Properties prop = new Properties();
        try(FileInputStream inputStream = new FileInputStream(fileName)){
            prop.load(inputStream);
        }catch (IOException e){
            System.err.println("加载文件失败" + fileName);
            System.err.println("错误原因" + e.getMessage());
            throw new RuntimeException("无法加载配置文件" + fileName, e);
        }
        return prop;
    }

//    public static Element[] randomP(int d, Element s, Pairing bp){
//        Element[] coef = new Element[d];
//        coef[0] = s;
//        for (int i=1; i<d; i++){
//            coef[i] = bp.getZr().newRandomElement().getImmutable();//先随机选择参数
//        }
//        return coef;
//    }
//
//    public static Element qx(Element index, Element[] coef, Pairing bp){
//        Element res = coef[0].getImmutable();
//        for (int i=1; i<coef.length; i++){
//            Element exp = bp.getZr().newElement(i).getImmutable();
//            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
//        }
//        return res;
//    }
//
//    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
//        Element res = bp.getZr().newOneElement().getImmutable();
//        Element iElement = bp.getZr().newElement(i).getImmutable();
//        Element xElement = bp.getZr().newElement(x).getImmutable();
//        for (int j : S) {
//            if (i != j) {
//                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
//                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
//                Element numerator = xElement.sub(bp.getZr().newElement(j));
//                Element denominator = iElement.sub(bp.getZr().newElement(j));
//                res = res.mul(numerator.div(denominator));
//            }
//        }
//        return res;
//    }
//
//    public static void nodeShare(Node[] nodes, Node n, Pairing bp){//输入：整个树、要分享的节点和bp
//        if(!n.isLeaf()){//检查当前节点是否为内部节点，因为叶子结点不需要多项式，直接跳过即可。
//            Element[] coef = randomP(n.gate[0], n.sharesecret, bp);
//            //生成多项式，n.gate[0]=kx，也就是解密所需的最小节点数
//            //n.sharesecret是当前节点的秘密值，
//            for (int j = 0; j < n.children.length; j++){//遍历子节点
//                Node childNode = nodes[n.children[j]]; //通过子节点ID从节点数组中获取子节点对象，n.children[j]：当前子节点的ID（如1,4,3等）
//                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
//                childNode.sharesecret = qx(bp.getZr().newElement(n.children[j]), coef, bp);
//                nodeShare(nodes, childNode, bp);
//            }
//        }
//    }
//
//    public static boolean nodeRecover(Node[] nodes, Node n, String[] atts, Pairing bp){//输入：整个树、要恢复的节点、属性集合
//        if(!n.isLeaf()){
//            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
//            List<Integer> validChildrenList = new ArrayList<Integer>();
//            int[] validChildren;
//            for(int i = 0; i < n.children.length; i++){
//                Node childNode = nodes[n.children[i]];
//                //递归调用子节点的子节点
//                if (nodeRecover(nodes, childNode, atts, bp)){
//                    validChildrenList.add(valueOf(n.children[i]));
//                    if(validChildrenList.size() == n.gate[0]){//这个等式说明有效的子节点数量已经=门限值
//                        n.valid = true;//n.valid 是一个标记位，表示该节点是否有效（即其子节点是否满足门限条件）。
//                        break;
//                    }
//                }
//            }
//
//            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
//            if(validChildrenList.size() == n.gate[0]){//list的长度满足门限值
//                validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
//                //validChildrenList.stream() 将List(整型)转为流。
//                //.mapToInt(i -> i)转为IntStream。
//                //.toArray();转为int[]数组。
//                Element secret = bp.getGT().newZeroElement().getImmutable();//选择一个秘密0，为了恢复。
//                for(int i : validChildren){
//                    Element delta = lagrange(i, validChildren, 0, bp);
//                    secret = secret.mul(nodes[i].sharesecret.duplicate().powZn(delta));
//                    //这里恢复密钥，可以去看论文中笔记的例子
//                }
//                n.sharesecret = secret;
//            }
//        }
//        else {
////            if (Arrays.asList(atts).contains(n.att)){
////                /* Arrays.stream(atts)将att数组转换为Stream流
////                  .boxed() 将原始类型的Stream转换为包装类型的Stream。如果 atts 是 int[] 或 long[]，.boxed() 会将原始类型（如 int）装箱为包装类型（如 Integer）。
////                  .collect(Collectors.toList())将流转为List
////                  .contains(n.att)检查n.att是否在List中*/
////                n.valid = true;
//            // 使用 Stream + trim() 确保精确匹配
//            boolean isMatched = Arrays.stream(atts)    //将数组转为流
//                    .map(String::trim)     //对每个属性的字符串调用 trim()，去掉首尾可能存在的多余空格。
//                    .anyMatch(attr -> attr.equals(n.att.trim())); //检查流中的任意元素（attr）是否严格等于 n.att（同样会先 trim()）
//            if (isMatched) {
//                n.valid = true;
//                System.out.println("✅ 属性匹配成功: " + n.att);
//            } else {
//                System.out.println("❌ 属性匹配失败: " + n.att + "（不在属性列表中）");
//            }
//        }
//        return n.valid;
//    }

    public static void main(String[] args) {
        String pairingParamsFileName = "a.properties";
        File paramFile = new File(pairingParamsFileName);
        if(!paramFile.exists()) {
            System.err.println("配对参数文件不存在" + paramFile.getAbsolutePath());
            System.err.println("请从JPBC库中添加参数文件");
            System.exit(-1);
        }

        String[] U = new String[100];
        for (int i = 0; i < 100; i++) {
            char letter = (char) ('A' + (i / 10)); // A(0-9), B(10-19), ..., J(90-99)
            int number = (i % 10) + 1;             // 1..10
            U[i] = String.format("%c%d", letter, number); // A1, A2, ..., J10
        }
        System.out.println("属性全集为：" + Arrays.toString(U));

        String[] messageAttList = {"E1", "B1","D1", "F1"};

        Node[] accessTree = new Node[7];
        accessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3});//根节点是2of3的门限，索引是123
        accessTree[1] = new Node("A1");
        accessTree[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
        accessTree[3] = new Node("E1");
        accessTree[4] = new Node("B1");
        accessTree[5] = new Node("C1");
        accessTree[6] = new Node("D1");

        String dir = "data/";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParamsFileName, U, pkFileName, mskFileName);

        keygen(pairingParamsFileName, accessTree, pkFileName, mskFileName, skFileName);

        Element message = getPairing(pairingParamsFileName).getGT().newRandomElement().getImmutable();

        encrypt(pairingParamsFileName, message, messageAttList, pkFileName, ctFileName);

        for (Node node : accessTree){
            node.sharesecret = null;
        }

        Element res = decrypt(pairingParamsFileName, accessTree, pkFileName, ctFileName, skFileName);
        System.out.println("\n=======================================");
        System.out.println("原始消息: " + message);
        System.out.println("解密消息: " + res);
        System.out.println("解密" + (message.equals(res) ? "成功 ✅" : "失败 ❌"));
        System.out.println("=======================================");
    }
}
