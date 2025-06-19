package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.analytics.ecommerce.a;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3435c3;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class zzow extends zzjo {
    private static final List zza;
    private static final Pattern zzb;
    private static final Pattern zzc;
    private static final zztp zzd;
    private static final zzto zze;
    private static final zzto zzf;
    private final zzji zzg;
    private final zzht zzh;
    private Map zzi;

    static {
        zza.UNIVERSAL_ANALYTICS.toString();
        zza = Arrays.asList("detail", "checkout", "checkout_option", "click", "add", "remove", "purchase", "refund");
        zzb = Pattern.compile("dimension(\\d+)");
        zzc = Pattern.compile("metric(\\d+)");
        zzd = zztp.zzi("", "0", "false");
        zze = zzto.zzc("transactionId", "&ti", "transactionAffiliation", "&ta", "transactionTax", "&tt", "transactionShipping", "&ts", "transactionTotal", "&tr", "transactionCurrency", "&cu");
        zzf = zzto.zzc("name", "&in", "sku", "&ic", "category", "&iv", "price", "&ip", "quantity", "&iq", "currency", "&cu");
    }

    public zzow(Context context, zzht zzhtVar) {
        zzji zzjiVar = new zzji(context);
        this.zzh = zzhtVar;
        this.zzg = zzjiVar;
    }

    private static final Map zzb(zzqo zzqoVar) {
        u.h(zzqoVar);
        u.b(zzqoVar instanceof zzqw);
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        zzra.zze(zzqoVar);
        Object objZzg = zzra.zzg(zzqoVar);
        u.k(objZzg instanceof Map);
        for (Map.Entry entry : ((Map) objZzg).entrySet()) {
            linkedHashMap.put(entry.getKey().toString(), entry.getValue().toString());
        }
        return linkedHashMap;
    }

    private static final Double zzc(Object obj) {
        if (obj instanceof String) {
            try {
                return Double.valueOf((String) obj);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Cannot convert the object to Double: ".concat(String.valueOf(e.getMessage())));
            }
        }
        if (obj instanceof Integer) {
            return Double.valueOf(((Integer) obj).doubleValue());
        }
        if (obj instanceof Double) {
            return (Double) obj;
        }
        throw new RuntimeException("Cannot convert the object to Double: ".concat(String.valueOf(obj.toString())));
    }

    private static final Integer zze(Object obj) {
        if (obj instanceof String) {
            try {
                return Integer.valueOf((String) obj);
            } catch (NumberFormatException e) {
                throw new RuntimeException("Cannot convert the object to Integer: ".concat(String.valueOf(e.getMessage())));
            }
        }
        if (obj instanceof Double) {
            return Integer.valueOf(((Double) obj).intValue());
        }
        if (obj instanceof Integer) {
            return (Integer) obj;
        }
        throw new RuntimeException("Cannot convert the object to Integer: ".concat(String.valueOf(obj.toString())));
    }

    private static final Map zzf(zzqo zzqoVar) {
        Map mapZzb = zzb(zzqoVar);
        String str = (String) mapZzb.get("&aip");
        if (str != null && zzd.contains(str.toLowerCase())) {
            mapZzb.remove("&aip");
        }
        return mapZzb;
    }

    private static final a zzg(Map map) throws NumberFormatException {
        a aVar = new a();
        Object obj = map.get("id");
        if (obj != null) {
            aVar.b("id", obj.toString());
        }
        Object obj2 = map.get("name");
        if (obj2 != null) {
            aVar.b("nm", obj2.toString());
        }
        Object obj3 = map.get("brand");
        if (obj3 != null) {
            aVar.b("br", obj3.toString());
        }
        Object obj4 = map.get("category");
        if (obj4 != null) {
            aVar.b(OTCCPAGeolocationConstants.CA, obj4.toString());
        }
        Object obj5 = map.get("variant");
        if (obj5 != null) {
            aVar.b("va", obj5.toString());
        }
        Object obj6 = map.get("coupon");
        if (obj6 != null) {
            aVar.b("cc", obj6.toString());
        }
        Object obj7 = map.get("position");
        if (obj7 != null) {
            aVar.b("ps", Integer.toString(zze(obj7).intValue()));
        }
        Object obj8 = map.get("price");
        if (obj8 != null) {
            aVar.b("pr", Double.toString(zzc(obj8).doubleValue()));
        }
        Object obj9 = map.get("quantity");
        if (obj9 != null) {
            aVar.b("qt", Integer.toString(zze(obj9).intValue()));
        }
        for (String str : map.keySet()) {
            Matcher matcher = zzb.matcher(str);
            if (matcher.matches()) {
                try {
                    int i = Integer.parseInt(matcher.group(1));
                    aVar.b(AbstractC3435c3.c(i, "cd"), String.valueOf(map.get(str)));
                } catch (NumberFormatException unused) {
                    zzhi.zze("illegal number in custom dimension value: ".concat(String.valueOf(str)));
                }
            } else {
                Matcher matcher2 = zzc.matcher(str);
                if (matcher2.matches()) {
                    try {
                        int i2 = Integer.parseInt(matcher2.group(1));
                        aVar.b(AbstractC3435c3.c(i2, "cm"), Integer.toString(zze(map.get(str)).intValue()));
                    } catch (NumberFormatException unused2) {
                        zzhi.zze("illegal number in custom metric value: ".concat(String.valueOf(str)));
                    }
                }
            }
        }
        return aVar;
    }

    /* JADX WARN: Code restructure failed: missing block: B:130:0x0220, code lost:
    
        r6 = (java.util.Map) r7.get(r5);
        r0 = (java.util.List) r6.get("products");
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x022f, code lost:
    
        if (r0 == null) goto L247;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x0231, code lost:
    
        r7 = r0.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x0239, code lost:
    
        if (r7.hasNext() == false) goto L247;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x0241, code lost:
    
        r0 = zzg((java.util.Map) r7.next());
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x0245, code lost:
    
        if (r0 != null) goto L268;
     */
    /* JADX WARN: Code restructure failed: missing block: B:138:0x0247, code lost:
    
        com.google.android.gms.internal.gtm.zzen.zze("product should be non-null");
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x024d, code lost:
    
        ((java.util.ArrayList) r2.e).add(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x0255, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x0256, code lost:
    
        com.google.android.gms.internal.gtm.zzhi.zza("Failed to extract a product from event data. ".concat(java.lang.String.valueOf(r0.getMessage())));
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x026a, code lost:
    
        if (r6.containsKey("actionField") == false) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x026c, code lost:
    
        r0 = (java.util.Map) r6.get("actionField");
        r3 = new com.quizlet.data.repository.school.membership.a(r5);
        r4 = r0.get("id");
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x027b, code lost:
    
        if (r4 == null) goto L151;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x027d, code lost:
    
        r3.u("&ti", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x0285, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x0288, code lost:
    
        r4 = r0.get("affiliation");
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x028e, code lost:
    
        if (r4 == null) goto L154;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x0290, code lost:
    
        r3.u("&ta", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x0299, code lost:
    
        r4 = r0.get("coupon");
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x029f, code lost:
    
        if (r4 == null) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x02a1, code lost:
    
        r3.u("&tcc", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x02aa, code lost:
    
        r4 = r0.get("list");
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x02ae, code lost:
    
        if (r4 == null) goto L160;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x02b0, code lost:
    
        r3.u("&pal", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x02b9, code lost:
    
        r4 = r0.get("option");
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x02bf, code lost:
    
        if (r4 == null) goto L163;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x02c1, code lost:
    
        r3.u("&col", r4.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x02ca, code lost:
    
        r4 = r0.get("revenue");
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x02d0, code lost:
    
        if (r4 == null) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x02d2, code lost:
    
        r3.u("&tr", java.lang.Double.toString(zzc(r4).doubleValue()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x02e3, code lost:
    
        r4 = r0.get("tax");
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x02e9, code lost:
    
        if (r4 == null) goto L169;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x02eb, code lost:
    
        r3.u("&tt", java.lang.Double.toString(zzc(r4).doubleValue()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x02fc, code lost:
    
        r4 = r0.get("shipping");
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0302, code lost:
    
        if (r4 == null) goto L172;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x0304, code lost:
    
        r3.u("&ts", java.lang.Double.toString(zzc(r4).doubleValue()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x0315, code lost:
    
        r0 = r0.get("step");
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x031b, code lost:
    
        if (r0 == null) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x031d, code lost:
    
        r3.u("&cos", java.lang.Integer.toString(zze(r0).intValue()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x032f, code lost:
    
        r3 = new com.quizlet.data.repository.school.membership.a(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x0334, code lost:
    
        r2.b = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x0337, code lost:
    
        com.google.android.gms.internal.gtm.zzhi.zza("Failed to extract a product action from event data. ".concat(java.lang.String.valueOf(r0.getMessage())));
     */
    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0214 A[Catch: all -> 0x0030, TryCatch #0 {all -> 0x0030, blocks: (B:7:0x0019, B:9:0x002d, B:15:0x003e, B:19:0x004b, B:23:0x0053, B:27:0x005b, B:31:0x0068, B:35:0x0075, B:39:0x007e, B:41:0x0088, B:43:0x0091, B:48:0x009e, B:50:0x00a3, B:54:0x00aa, B:56:0x00af, B:60:0x00b8, B:63:0x00d9, B:67:0x00f1, B:69:0x00f7, B:71:0x0107, B:73:0x010b, B:75:0x0115, B:77:0x011f, B:78:0x0122, B:81:0x0130, B:82:0x0136, B:84:0x013c, B:85:0x0142, B:88:0x0151, B:89:0x0161, B:92:0x0169, B:100:0x018e, B:101:0x0192, B:103:0x0198, B:104:0x019e, B:106:0x01ab, B:107:0x01ae, B:109:0x01b6, B:110:0x01bb, B:112:0x01c5, B:113:0x01ca, B:115:0x01d4, B:116:0x01d9, B:119:0x01e2, B:120:0x01f4, B:123:0x01fc, B:124:0x0203, B:125:0x0208, B:126:0x020e, B:128:0x0214, B:130:0x0220, B:132:0x0231, B:133:0x0235, B:135:0x023b, B:136:0x0241, B:138:0x0247, B:139:0x024d, B:142:0x0256, B:144:0x0266, B:146:0x026c, B:148:0x027d, B:151:0x0288, B:153:0x0290, B:154:0x0299, B:156:0x02a1, B:157:0x02aa, B:159:0x02b0, B:160:0x02b9, B:162:0x02c1, B:163:0x02ca, B:165:0x02d2, B:166:0x02e3, B:168:0x02eb, B:169:0x02fc, B:171:0x0304, B:172:0x0315, B:174:0x031d, B:176:0x0334, B:175:0x032f, B:178:0x0337, B:93:0x0176, B:95:0x017c, B:179:0x0348, B:70:0x0100, B:66:0x00e5, B:181:0x0352, B:183:0x0358, B:184:0x0360, B:186:0x0366, B:188:0x0372, B:189:0x0378, B:190:0x037d, B:192:0x0388, B:196:0x0392, B:197:0x039a, B:199:0x03a0, B:201:0x03b4, B:202:0x03be, B:216:0x03f0, B:217:0x03f4, B:219:0x03fa, B:221:0x0406, B:222:0x040d, B:224:0x041d, B:226:0x0424, B:227:0x042c, B:229:0x0432, B:231:0x0442, B:232:0x0450, B:225:0x0420, B:233:0x0454, B:234:0x0458, B:236:0x045e, B:205:0x03cd, B:207:0x03d1, B:208:0x03d7, B:210:0x03dd, B:213:0x03e6, B:214:0x03ed, B:237:0x0468, B:238:0x046f, B:195:0x038e, B:239:0x0470, B:240:0x0477, B:40:0x0081, B:36:0x0078, B:32:0x006b, B:28:0x005e, B:24:0x0056, B:20:0x004e, B:16:0x0041, B:12:0x0034), top: B:246:0x0019, inners: #1, #2, #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:181:0x0352 A[Catch: all -> 0x0030, TryCatch #0 {all -> 0x0030, blocks: (B:7:0x0019, B:9:0x002d, B:15:0x003e, B:19:0x004b, B:23:0x0053, B:27:0x005b, B:31:0x0068, B:35:0x0075, B:39:0x007e, B:41:0x0088, B:43:0x0091, B:48:0x009e, B:50:0x00a3, B:54:0x00aa, B:56:0x00af, B:60:0x00b8, B:63:0x00d9, B:67:0x00f1, B:69:0x00f7, B:71:0x0107, B:73:0x010b, B:75:0x0115, B:77:0x011f, B:78:0x0122, B:81:0x0130, B:82:0x0136, B:84:0x013c, B:85:0x0142, B:88:0x0151, B:89:0x0161, B:92:0x0169, B:100:0x018e, B:101:0x0192, B:103:0x0198, B:104:0x019e, B:106:0x01ab, B:107:0x01ae, B:109:0x01b6, B:110:0x01bb, B:112:0x01c5, B:113:0x01ca, B:115:0x01d4, B:116:0x01d9, B:119:0x01e2, B:120:0x01f4, B:123:0x01fc, B:124:0x0203, B:125:0x0208, B:126:0x020e, B:128:0x0214, B:130:0x0220, B:132:0x0231, B:133:0x0235, B:135:0x023b, B:136:0x0241, B:138:0x0247, B:139:0x024d, B:142:0x0256, B:144:0x0266, B:146:0x026c, B:148:0x027d, B:151:0x0288, B:153:0x0290, B:154:0x0299, B:156:0x02a1, B:157:0x02aa, B:159:0x02b0, B:160:0x02b9, B:162:0x02c1, B:163:0x02ca, B:165:0x02d2, B:166:0x02e3, B:168:0x02eb, B:169:0x02fc, B:171:0x0304, B:172:0x0315, B:174:0x031d, B:176:0x0334, B:175:0x032f, B:178:0x0337, B:93:0x0176, B:95:0x017c, B:179:0x0348, B:70:0x0100, B:66:0x00e5, B:181:0x0352, B:183:0x0358, B:184:0x0360, B:186:0x0366, B:188:0x0372, B:189:0x0378, B:190:0x037d, B:192:0x0388, B:196:0x0392, B:197:0x039a, B:199:0x03a0, B:201:0x03b4, B:202:0x03be, B:216:0x03f0, B:217:0x03f4, B:219:0x03fa, B:221:0x0406, B:222:0x040d, B:224:0x041d, B:226:0x0424, B:227:0x042c, B:229:0x0432, B:231:0x0442, B:232:0x0450, B:225:0x0420, B:233:0x0454, B:234:0x0458, B:236:0x045e, B:205:0x03cd, B:207:0x03d1, B:208:0x03d7, B:210:0x03dd, B:213:0x03e6, B:214:0x03ed, B:237:0x0468, B:238:0x046f, B:195:0x038e, B:239:0x0470, B:240:0x0477, B:40:0x0081, B:36:0x0078, B:32:0x006b, B:28:0x005e, B:24:0x0056, B:20:0x004e, B:16:0x0041, B:12:0x0034), top: B:246:0x0019, inners: #1, #2, #3, #4, #5 }] */
    /* JADX WARN: Removed duplicated region for block: B:236:0x045e A[Catch: all -> 0x0030, IllegalArgumentException -> 0x038b, LOOP:7: B:234:0x0458->B:236:0x045e, LOOP_END, TryCatch #4 {IllegalArgumentException -> 0x038b, blocks: (B:190:0x037d, B:192:0x0388, B:196:0x0392, B:197:0x039a, B:199:0x03a0, B:201:0x03b4, B:202:0x03be, B:216:0x03f0, B:217:0x03f4, B:219:0x03fa, B:221:0x0406, B:222:0x040d, B:224:0x041d, B:226:0x0424, B:227:0x042c, B:229:0x0432, B:231:0x0442, B:232:0x0450, B:225:0x0420, B:233:0x0454, B:234:0x0458, B:236:0x045e, B:205:0x03cd, B:207:0x03d1, B:208:0x03d7, B:210:0x03dd, B:213:0x03e6, B:214:0x03ed, B:237:0x0468, B:238:0x046f, B:195:0x038e), top: B:253:0x037d, outer: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:266:0x0348 A[EDGE_INSN: B:266:0x0348->B:179:0x0348 BREAK  A[LOOP:2: B:126:0x020e->B:267:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00d9 A[Catch: all -> 0x0030, TRY_ENTER, TryCatch #0 {all -> 0x0030, blocks: (B:7:0x0019, B:9:0x002d, B:15:0x003e, B:19:0x004b, B:23:0x0053, B:27:0x005b, B:31:0x0068, B:35:0x0075, B:39:0x007e, B:41:0x0088, B:43:0x0091, B:48:0x009e, B:50:0x00a3, B:54:0x00aa, B:56:0x00af, B:60:0x00b8, B:63:0x00d9, B:67:0x00f1, B:69:0x00f7, B:71:0x0107, B:73:0x010b, B:75:0x0115, B:77:0x011f, B:78:0x0122, B:81:0x0130, B:82:0x0136, B:84:0x013c, B:85:0x0142, B:88:0x0151, B:89:0x0161, B:92:0x0169, B:100:0x018e, B:101:0x0192, B:103:0x0198, B:104:0x019e, B:106:0x01ab, B:107:0x01ae, B:109:0x01b6, B:110:0x01bb, B:112:0x01c5, B:113:0x01ca, B:115:0x01d4, B:116:0x01d9, B:119:0x01e2, B:120:0x01f4, B:123:0x01fc, B:124:0x0203, B:125:0x0208, B:126:0x020e, B:128:0x0214, B:130:0x0220, B:132:0x0231, B:133:0x0235, B:135:0x023b, B:136:0x0241, B:138:0x0247, B:139:0x024d, B:142:0x0256, B:144:0x0266, B:146:0x026c, B:148:0x027d, B:151:0x0288, B:153:0x0290, B:154:0x0299, B:156:0x02a1, B:157:0x02aa, B:159:0x02b0, B:160:0x02b9, B:162:0x02c1, B:163:0x02ca, B:165:0x02d2, B:166:0x02e3, B:168:0x02eb, B:169:0x02fc, B:171:0x0304, B:172:0x0315, B:174:0x031d, B:176:0x0334, B:175:0x032f, B:178:0x0337, B:93:0x0176, B:95:0x017c, B:179:0x0348, B:70:0x0100, B:66:0x00e5, B:181:0x0352, B:183:0x0358, B:184:0x0360, B:186:0x0366, B:188:0x0372, B:189:0x0378, B:190:0x037d, B:192:0x0388, B:196:0x0392, B:197:0x039a, B:199:0x03a0, B:201:0x03b4, B:202:0x03be, B:216:0x03f0, B:217:0x03f4, B:219:0x03fa, B:221:0x0406, B:222:0x040d, B:224:0x041d, B:226:0x0424, B:227:0x042c, B:229:0x0432, B:231:0x0442, B:232:0x0450, B:225:0x0420, B:233:0x0454, B:234:0x0458, B:236:0x045e, B:205:0x03cd, B:207:0x03d1, B:208:0x03d7, B:210:0x03dd, B:213:0x03e6, B:214:0x03ed, B:237:0x0468, B:238:0x046f, B:195:0x038e, B:239:0x0470, B:240:0x0477, B:40:0x0081, B:36:0x0078, B:32:0x006b, B:28:0x005e, B:24:0x0056, B:20:0x004e, B:16:0x0041, B:12:0x0034), top: B:246:0x0019, inners: #1, #2, #3, #4, #5 }] */
    @Override // com.google.android.gms.internal.gtm.zzjo
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.gtm.zzqo zza(com.google.android.gms.internal.gtm.zzhx r18, com.google.android.gms.internal.gtm.zzqo... r19) {
        /*
            Method dump skipped, instructions count: 1158
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzow.zza(com.google.android.gms.internal.gtm.zzhx, com.google.android.gms.internal.gtm.zzqo[]):com.google.android.gms.internal.gtm.zzqo");
    }
}
