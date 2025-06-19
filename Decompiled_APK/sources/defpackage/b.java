package defpackage;

import java.util.LinkedHashMap;
import kotlin.Pair;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.s;

/* loaded from: classes.dex */
public abstract class b {
    public static final Regex a = new Regex("(shuang|chuang|zhuang|xiang|qiong|shuai|niang|guang|sheng|kuang|shang|jiong|huang|jiang|shuan|xiong|zhang|zheng|zhong|zhuai|zhuan|qiang|chang|liang|chuan|cheng|chong|chuai|hang|peng|chuo|piao|pian|chua|ping|yang|pang|chui|chun|chen|chan|chou|chao|chai|zhun|mang|meng|weng|shai|shei|miao|zhui|mian|yong|ming|wang|zhuo|zhua|shao|yuan|bing|zhen|fang|feng|zhan|zhou|zhao|zhei|zhai|rang|suan|reng|song|seng|dang|deng|dong|xuan|sang|rong|duan|cuan|cong|ceng|cang|diao|ruan|dian|ding|shou|xing|zuan|jiao|zong|zeng|zang|jian|tang|teng|tong|bian|biao|shan|tuan|huan|xian|huai|tiao|tian|hong|xiao|heng|ying|jing|shen|beng|kuan|kuai|nang|neng|nong|juan|kong|nuan|keng|kang|shua|niao|guan|nian|ting|shuo|guai|ning|quan|qiao|shui|gong|geng|gang|qian|bang|lang|leng|long|qing|ling|luan|shun|lian|liao|zhi|lia|liu|qin|lun|lin|luo|lan|lou|qiu|gai|gei|gao|gou|gan|gen|lao|lei|lai|que|gua|guo|nin|gui|niu|nie|gun|qie|qia|jun|kai|kei|kao|kou|kan|ken|qun|nun|nuo|xia|kua|kuo|nen|kui|nan|nou|kun|jue|nao|nei|hai|hei|hao|hou|han|hen|nai|rou|xiu|jin|hua|huo|tie|hui|tun|tui|hun|tuo|tan|jiu|zai|zei|zao|zou|zan|zen|eng|tou|tao|tei|tai|zuo|zui|xin|zun|jie|jia|run|diu|cai|cao|cou|can|cen|die|dia|xue|rui|cuo|cui|dun|cun|cin|ruo|rua|dui|sai|sao|sou|san|sen|duo|den|dan|dou|suo|sui|dao|sun|dei|zha|zhe|dai|xun|ang|ong|wai|fen|fan|fou|fei|zhu|wei|wan|min|miu|mie|wen|men|lie|chi|cha|che|man|mou|mao|mei|mai|yao|you|yan|chu|pin|pie|yin|pen|pan|pou|pao|shi|sha|she|pei|pai|yue|bin|bie|yun|nüe|lve|shu|ben|ban|bao|bei|bai|lüe|nve|ren|ran|rao|xie|re|ri|si|su|se|ru|sa|cu|ce|ca|ji|ci|zi|zu|ze|za|hu|he|ha|ju|ku|ke|qi|ka|gu|ge|ga|li|lu|le|qu|la|ni|xi|nu|ne|na|ti|tu|te|ta|xu|di|du|de|bo|lv|ba|ai|ei|ao|ou|an|en|er|da|wu|wa|wo|fu|fo|fa|nv|mi|mu|yi|ya|ye|me|mo|ma|pi|pu|po|yu|pa|bi|nü|bu|lü|e|o|a)r?[1-5]", s.b);
    public static final Regex b = new Regex(".\\*");
    public static final Object c = V.f(new Pair("a*", 0), new Pair("e*", 1), new Pair("i*", 2), new Pair("o*", 3), new Pair("u*", 4), new Pair("ü*", 5), new Pair("A*", 6), new Pair("E*", 7), new Pair("I*", 8), new Pair("O*", 9), new Pair("U*", 10), new Pair("Ü*", 11));
    public static final Object d = V.f(new Pair(1, new String[]{"ā", "ē", "ī", "ō", "ū", "ǖ", "Ā", "Ē", "Ī", "Ō", "Ū", "Ǖ"}), new Pair(2, new String[]{"á", "é", "í", "ó", "ú", "ǘ", "Á", "É", "Í", "Ó", "Ú", "Ǘ"}), new Pair(3, new String[]{"ǎ", "ě", "ǐ", "ǒ", "ǔ", "ǚ", "Ǎ", "Ě", "Ǐ", "Ǒ", "Ǔ", "Ǚ"}), new Pair(4, new String[]{"à", "è", "ì", "ò", "ù", "ǜ", "À", "È", "Ì", "Ò", "Ù", "Ǜ"}), new Pair(5, new String[]{"a", "e", "i", "o", "u", "ü", "A", "E", "I", "O", "U", "Ü"}));
    public static final LinkedHashMap e;

    static {
        String[] strArr = {"a*i", "a*o", "e*i", "ia*", "ia*o", "ie*", "io*", "iu*", "A*I", "A*O", "E*I", "IA*", "IA*O", "IE*", "IO*", "IU*", "o*u", "ua*", "ua*i", "ue*", "ui*", "uo*", "üe*", "O*U", "UA*", "UA*I", "UE*", "UI*", "UO*", "ÜE*", "A*", "E*", "I*", "O*", "U*", "Ü*", "a*", "e*", "i*", "o*", "u*", "ü*"};
        int iA = U.a(42);
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (int i = 0; i < 42; i++) {
            String str = strArr[i];
            linkedHashMap.put(D.o(str, "*", "", false), str);
        }
        e = linkedHashMap;
    }
}
