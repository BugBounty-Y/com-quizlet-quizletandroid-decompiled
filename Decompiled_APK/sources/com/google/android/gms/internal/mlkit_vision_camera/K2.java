package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Build;
import android.text.Editable;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import assistantMode.types.C1455b;
import com.comscore.streaming.ContentType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.AztecStyleSpan;

/* loaded from: classes2.dex */
public abstract class K2 {
    public static final void a(kotlinx.coroutines.flow.Y navigationFlow, com.quizlet.features.questiontypes.basequestion.i questionViewModel, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(navigationFlow, "navigationFlow");
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(937048024);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(navigationFlow) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(questionViewModel) : c0814p.h(questionViewModel) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.lifecycle.C lifecycle = ((androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a)).getLifecycle();
            c0814p.X(-586731904);
            boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32 || ((i2 & 64) != 0 && c0814p.h(questionViewModel))) | c0814p.h(lifecycle) | c0814p.h(navigationFlow);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.questiontypes.composables.g(lifecycle, navigationFlow, questionViewModel, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.g(navigationFlow, lifecycle, (Function2) objI, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(navigationFlow, questionViewModel, i, 19);
        }
    }

    public static void b(Editable editable, int i, int i2, String str, int i3, int i4) {
        if (i < 0 || i2 < 0 || i > editable.length() || i2 > editable.length() || i >= i2) {
            return;
        }
        Matcher matcher = Pattern.compile(str).matcher(editable.subSequence(i, i2));
        while (matcher.find()) {
            int iStart = matcher.start() + i;
            int iEnd = matcher.end() + i;
            if (str.equals("(<\\/?[a-z][^<>]*>)")) {
                editable.setSpan(new ForegroundColorSpan(i3), iStart, iEnd, 33);
            } else if (str.equals("(?<==)('|\")(.*?\\1)(?=.*?>)")) {
                editable.setSpan(new ForegroundColorSpan(i4), iStart, iEnd, 33);
            } else if (str.equals("(<!--.*?-->)")) {
                editable.setSpan(new ForegroundColorSpan(i4), iStart, iEnd, 33);
            } else if (str.equals("(&#34;|&#38;|&#39;|&#60;|&#62;|&#160;|&#161;|&#162;|&#163;|&#164;|&#165;|&#166;|&#167;|&#168;|&#169;|&#170;|&#171;|&#172;|&#173;|&#174;|&#175;|&#176;|&#177;|&#178;|&#179;|&#180;|&#181;|&#182;|&#183;|&#184;|&#185;|&#186;|&#187;|&#188;|&#189;|&#190;|&#191;|&#192;|&#193;|&#194;|&#195;|&#196;|&#197;|&#198;|&#199;|&#200;|&#201;|&#202;|&#203;|&#204;|&#205;|&#206;|&#207;|&#208;|&#209;|&#210;|&#211;|&#212;|&#213;|&#214;|&#215;|&#216;|&#217;|&#218;|&#219;|&#220;|&#221;|&#222;|&#223;|&#224;|&#225;|&#226;|&#227;|&#228;|&#229;|&#230;|&#231;|&#232;|&#233;|&#234;|&#235;|&#236;|&#237;|&#238;|&#239;|&#240;|&#241;|&#242;|&#243;|&#244;|&#245;|&#246;|&#247;|&#248;|&#249;|&#250;|&#251;|&#252;|&#253;|&#254;|&#255;|&#338;|&#339;|&#352;|&#353;|&#376;|&#402;|&#710;|&#732;|&#913;|&#914;|&#915;|&#916;|&#917;|&#918;|&#919;|&#920;|&#921;|&#922;|&#923;|&#924;|&#925;|&#926;|&#927;|&#928;|&#929;|&#931;|&#932;|&#933;|&#934;|&#935;|&#936;|&#937;|&#945;|&#946;|&#947;|&#948;|&#949;|&#950;|&#951;|&#952;|&#953;|&#954;|&#955;|&#956;|&#957;|&#958;|&#959;|&#960;|&#961;|&#962;|&#963;|&#964;|&#965;|&#966;|&#967;|&#968;|&#969;|&#977;|&#978;|&#982;|&#8194;|&#8195;|&#8201;|&#8204;|&#8205;|&#8206;|&#8207;|&#8211;|&#8212;|&#8216;|&#8217;|&#8218;|&#8220;|&#8221;|&#8222;|&#8224;|&#8225;|&#8226;|&#8230;|&#8240;|&#8242;|&#8243;|&#8249;|&#8250;|&#8254;|&#8260;|&#8364;|&#8465;|&#8472;|&#8476;|&#8482;|&#8501;|&#8592;|&#8593;|&#8594;|&#8595;|&#8596;|&#8629;|&#8656;|&#8657;|&#8658;|&#8659;|&#8660;|&#8704;|&#8706;|&#8707;|&#8709;|&#8711;|&#8712;|&#8713;|&#8715;|&#8719;|&#8721;|&#8722;|&#8727;|&#8730;|&#8733;|&#8734;|&#8736;|&#8743;|&#8744;|&#8745;|&#8746;|&#8747;|&#8756;|&#8764;|&#8773;|&#8776;|&#8800;|&#8801;|&#8804;|&#8805;|&#8834;|&#8835;|&#8836;|&#8838;|&#8839;|&#8853;|&#8855;|&#8869;|&#8901;|&#8968;|&#8969;|&#8970;|&#8971;|&#9001;|&#9002;|&#9674;|&#9824;|&#9827;|&#9829;|&#9830;|&quot;|&amp;|&apos;|&lt;|&gt;|&nbsp;|&iexcl;|&cent;|&pound;|&curren;|&yen;|&brvbar;|&sect;|&uml;|&copy;|&ordf;|&laquo;|&not;|&shy;|&reg;|&macr;|&deg;|&plusmn;|&sup2;|&sup3;|&acute;|&micro;|&para;|&middot;|&cedil;|&sup1;|&ordm;|&raquo;|&frac14;|&frac12;|&frac34;|&iquest;|&Agrave;|&Aacute;|&Acirc;|&Atilde;|&Auml;|&Aring;|&AElig;|&Ccedil;|&Egrave;|&Eacute;|&Ecirc;|&Euml;|&Igrave;|&Iacute;|&Icirc;|&Iuml;|&ETH;|&Ntilde;|&Ograve;|&Oacute;|&Ocirc;|&Otilde;|&Ouml;|&times;|&Oslash;|&Ugrave;|&Uacute;|&Ucirc;|&Uuml;|&Yacute;|&THORN;|&szlig;|&agrave;|&aacute;|&acirc;|&atilde;|&auml;|&aring;|&aelig;|&ccedil;|&egrave;|&eacute;|&ecirc;|&euml;|&igrave;|&iacute;|&icirc;|&iuml;|&eth;|&ntilde;|&ograve;|&oacute;|&ocirc;|&otilde;|&ouml;|&divide;|&oslash;|&Ugrave;|&Uacute;|&Ucirc;|&Uuml;|&yacute;|&thorn;|&yuml;|&OElig;|&oelig;|&Scaron;|&scaron;|&Yuml;|&fnof;|&circ;|&tilde;|&Alpha;|&Beta;|&Gamma;|&Delta;|&Epsilon;|&Zeta;|&Eta;|&Theta;|&Iota;|&Kappa;|&Lambda;|&Mu;|&Nu;|&Xi;|&Omicron;|&Pi;|&Rho;|&Sigma;|&Tau;|&Upsilon;|&Phi;|&Chi;|&Psi;|&Omega;|&alpha;|&beta;|&gamma;|&delta;|&epsilon;|&zeta;|&eta;|&theta;|&iota;|&kappa;|&lambda;|&mu;|&nu;|&xi;|&omicron;|&pi;|&rho;|&sigmaf;|&sigma;|&tau;|&upsilon;|&phi;|&chi;|&psi;|&omega;|&thetasym;|&Upsih;|&piv;|&ensp;|&emsp;|&thinsp;|&zwnj;|&zwj;|&lrm;|&rlm;|&ndash;|&mdash;|&lsquo;|&rsquo;|&sbquo;|&ldquo;|&rdquo;|&bdquo;|&dagger;|&Dagger;|&bull;|&hellip;|&permil;|&prime;|&Prime;|&lsaquo;|&rsaquo;|&oline;|&frasl;|&euro;|&image;|&weierp;|&real;|&trade;|&alefsym;|&larr;|&uarr;|&rarr;|&darr;|&harr;|&crarr;|&lArr;|&UArr;|&rArr;|&dArr;|&hArr;|&forall;|&part;|&exist;|&empty;|&nabla;|&isin;|&notin;|&ni;|&prod;|&sum;|&minus;|&lowast;|&radic;|&prop;|&infin;|&ang;|&and;|&or;|&cap;|&cup;|&int;|&there4;|&sim;|&cong;|&asymp;|&ne;|&equiv;|&le;|&ge;|&sub;|&sup;|&nsub;|&sube;|&supe;|&oplus;|&otimes;|&perp;|&sdot;|&lceil;|&rceil;|&lfloor;|&rfloor;|&lang;|&rang;|&loz;|&spades;|&clubs;|&hearts;|&diams;)")) {
                editable.setSpan(new ForegroundColorSpan(i3), iStart, iEnd, 33);
                editable.setSpan(new AztecStyleSpan(1), iStart, iEnd, 33);
                editable.setSpan(new RelativeSizeSpan(0.75f), iStart, iEnd, 33);
            }
        }
    }

    public static final LinkedHashMap c(long j, List list) {
        Double dValueOf;
        Object objPrevious;
        List list2 = assistantMode.a.b;
        int iA = kotlin.collections.U.a(kotlin.collections.C.q(list2, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : list2) {
            assistantMode.enums.m mVar = (assistantMode.enums.m) obj;
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : list) {
                if (((C1455b) obj2).c == mVar) {
                    arrayList.add(obj2);
                }
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(Long.valueOf(((C1455b) it2.next()).f));
            }
            ListIterator listIterator = arrayList2.listIterator(arrayList2.size());
            while (true) {
                dValueOf = null;
                if (!listIterator.hasPrevious()) {
                    objPrevious = null;
                    break;
                }
                objPrevious = listIterator.previous();
                if (((Number) objPrevious).longValue() < j) {
                    break;
                }
            }
            if (((Long) objPrevious) != null) {
                dValueOf = Double.valueOf((j - r5.longValue()) * 0.001d);
            }
            linkedHashMap.put(obj, dValueOf);
        }
        return linkedHashMap;
    }

    public static void d(Editable content, int i, int i2, int i3, int i4) {
        Intrinsics.checkNotNullParameter(content, "content");
        String str = Build.VERSION.RELEASE;
        if (Intrinsics.b(str, "4.1") || Intrinsics.b(str, "4.1.1")) {
            return;
        }
        b(content, i, i2, "(<\\/?[a-z][^<>]*>)", i3, i4);
        b(content, i, i2, "(?<==)('|\")(.*?\\1)(?=.*?>)", i3, i4);
        b(content, i, i2, "(<!--.*?-->)", i3, i4);
        b(content, i, i2, "(&#34;|&#38;|&#39;|&#60;|&#62;|&#160;|&#161;|&#162;|&#163;|&#164;|&#165;|&#166;|&#167;|&#168;|&#169;|&#170;|&#171;|&#172;|&#173;|&#174;|&#175;|&#176;|&#177;|&#178;|&#179;|&#180;|&#181;|&#182;|&#183;|&#184;|&#185;|&#186;|&#187;|&#188;|&#189;|&#190;|&#191;|&#192;|&#193;|&#194;|&#195;|&#196;|&#197;|&#198;|&#199;|&#200;|&#201;|&#202;|&#203;|&#204;|&#205;|&#206;|&#207;|&#208;|&#209;|&#210;|&#211;|&#212;|&#213;|&#214;|&#215;|&#216;|&#217;|&#218;|&#219;|&#220;|&#221;|&#222;|&#223;|&#224;|&#225;|&#226;|&#227;|&#228;|&#229;|&#230;|&#231;|&#232;|&#233;|&#234;|&#235;|&#236;|&#237;|&#238;|&#239;|&#240;|&#241;|&#242;|&#243;|&#244;|&#245;|&#246;|&#247;|&#248;|&#249;|&#250;|&#251;|&#252;|&#253;|&#254;|&#255;|&#338;|&#339;|&#352;|&#353;|&#376;|&#402;|&#710;|&#732;|&#913;|&#914;|&#915;|&#916;|&#917;|&#918;|&#919;|&#920;|&#921;|&#922;|&#923;|&#924;|&#925;|&#926;|&#927;|&#928;|&#929;|&#931;|&#932;|&#933;|&#934;|&#935;|&#936;|&#937;|&#945;|&#946;|&#947;|&#948;|&#949;|&#950;|&#951;|&#952;|&#953;|&#954;|&#955;|&#956;|&#957;|&#958;|&#959;|&#960;|&#961;|&#962;|&#963;|&#964;|&#965;|&#966;|&#967;|&#968;|&#969;|&#977;|&#978;|&#982;|&#8194;|&#8195;|&#8201;|&#8204;|&#8205;|&#8206;|&#8207;|&#8211;|&#8212;|&#8216;|&#8217;|&#8218;|&#8220;|&#8221;|&#8222;|&#8224;|&#8225;|&#8226;|&#8230;|&#8240;|&#8242;|&#8243;|&#8249;|&#8250;|&#8254;|&#8260;|&#8364;|&#8465;|&#8472;|&#8476;|&#8482;|&#8501;|&#8592;|&#8593;|&#8594;|&#8595;|&#8596;|&#8629;|&#8656;|&#8657;|&#8658;|&#8659;|&#8660;|&#8704;|&#8706;|&#8707;|&#8709;|&#8711;|&#8712;|&#8713;|&#8715;|&#8719;|&#8721;|&#8722;|&#8727;|&#8730;|&#8733;|&#8734;|&#8736;|&#8743;|&#8744;|&#8745;|&#8746;|&#8747;|&#8756;|&#8764;|&#8773;|&#8776;|&#8800;|&#8801;|&#8804;|&#8805;|&#8834;|&#8835;|&#8836;|&#8838;|&#8839;|&#8853;|&#8855;|&#8869;|&#8901;|&#8968;|&#8969;|&#8970;|&#8971;|&#9001;|&#9002;|&#9674;|&#9824;|&#9827;|&#9829;|&#9830;|&quot;|&amp;|&apos;|&lt;|&gt;|&nbsp;|&iexcl;|&cent;|&pound;|&curren;|&yen;|&brvbar;|&sect;|&uml;|&copy;|&ordf;|&laquo;|&not;|&shy;|&reg;|&macr;|&deg;|&plusmn;|&sup2;|&sup3;|&acute;|&micro;|&para;|&middot;|&cedil;|&sup1;|&ordm;|&raquo;|&frac14;|&frac12;|&frac34;|&iquest;|&Agrave;|&Aacute;|&Acirc;|&Atilde;|&Auml;|&Aring;|&AElig;|&Ccedil;|&Egrave;|&Eacute;|&Ecirc;|&Euml;|&Igrave;|&Iacute;|&Icirc;|&Iuml;|&ETH;|&Ntilde;|&Ograve;|&Oacute;|&Ocirc;|&Otilde;|&Ouml;|&times;|&Oslash;|&Ugrave;|&Uacute;|&Ucirc;|&Uuml;|&Yacute;|&THORN;|&szlig;|&agrave;|&aacute;|&acirc;|&atilde;|&auml;|&aring;|&aelig;|&ccedil;|&egrave;|&eacute;|&ecirc;|&euml;|&igrave;|&iacute;|&icirc;|&iuml;|&eth;|&ntilde;|&ograve;|&oacute;|&ocirc;|&otilde;|&ouml;|&divide;|&oslash;|&Ugrave;|&Uacute;|&Ucirc;|&Uuml;|&yacute;|&thorn;|&yuml;|&OElig;|&oelig;|&Scaron;|&scaron;|&Yuml;|&fnof;|&circ;|&tilde;|&Alpha;|&Beta;|&Gamma;|&Delta;|&Epsilon;|&Zeta;|&Eta;|&Theta;|&Iota;|&Kappa;|&Lambda;|&Mu;|&Nu;|&Xi;|&Omicron;|&Pi;|&Rho;|&Sigma;|&Tau;|&Upsilon;|&Phi;|&Chi;|&Psi;|&Omega;|&alpha;|&beta;|&gamma;|&delta;|&epsilon;|&zeta;|&eta;|&theta;|&iota;|&kappa;|&lambda;|&mu;|&nu;|&xi;|&omicron;|&pi;|&rho;|&sigmaf;|&sigma;|&tau;|&upsilon;|&phi;|&chi;|&psi;|&omega;|&thetasym;|&Upsih;|&piv;|&ensp;|&emsp;|&thinsp;|&zwnj;|&zwj;|&lrm;|&rlm;|&ndash;|&mdash;|&lsquo;|&rsquo;|&sbquo;|&ldquo;|&rdquo;|&bdquo;|&dagger;|&Dagger;|&bull;|&hellip;|&permil;|&prime;|&Prime;|&lsaquo;|&rsaquo;|&oline;|&frasl;|&euro;|&image;|&weierp;|&real;|&trade;|&alefsym;|&larr;|&uarr;|&rarr;|&darr;|&harr;|&crarr;|&lArr;|&UArr;|&rArr;|&dArr;|&hArr;|&forall;|&part;|&exist;|&empty;|&nabla;|&isin;|&notin;|&ni;|&prod;|&sum;|&minus;|&lowast;|&radic;|&prop;|&infin;|&ang;|&and;|&or;|&cap;|&cup;|&int;|&there4;|&sim;|&cong;|&asymp;|&ne;|&equiv;|&le;|&ge;|&sub;|&sup;|&nsub;|&sube;|&supe;|&oplus;|&otimes;|&perp;|&sdot;|&lceil;|&rceil;|&lfloor;|&rfloor;|&lang;|&rang;|&loz;|&spades;|&clubs;|&hearts;|&diams;)", i3, i4);
    }
}
