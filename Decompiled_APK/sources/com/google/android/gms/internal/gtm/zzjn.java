package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import android.text.TextUtils;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public abstract class zzjn {
    public static double zza(zzqo zzqoVar) throws NumberFormatException {
        double dZzb = zzb(zzqoVar);
        if (Double.isNaN(dZzb)) {
            return 0.0d;
        }
        if (dZzb == 0.0d || dZzb == 0.0d || Double.isInfinite(dZzb)) {
            return dZzb;
        }
        return Math.floor(Math.abs(dZzb)) * Math.signum(dZzb);
    }

    public static double zzb(zzqo zzqoVar) throws NumberFormatException {
        u.b(zzqoVar != null);
        if (zzqoVar == zzqs.zze) {
            return Double.NaN;
        }
        if (zzqoVar == zzqs.zzd) {
            return 0.0d;
        }
        if (zzqoVar instanceof zzqp) {
            return ((zzqp) zzqoVar).zzi().booleanValue() ? 1.0d : 0.0d;
        }
        if (zzqoVar instanceof zzqq) {
            return ((zzqq) zzqoVar).zzi().doubleValue();
        }
        if (zzqoVar instanceof zzqv) {
            zzqv zzqvVar = (zzqv) zzqoVar;
            if (zzqvVar.zzk().isEmpty()) {
                return 0.0d;
            }
            if (zzqvVar.zzk().size() == 1) {
                return zzb(new zzqz(zzd(zzqvVar.zzi(0))));
            }
        } else if (zzqoVar instanceof zzqz) {
            zzqz zzqzVar = (zzqz) zzqoVar;
            if (zzqzVar.zzk().isEmpty()) {
                return 0.0d;
            }
            try {
                return Double.parseDouble(zzqzVar.zzk());
            } catch (NumberFormatException unused) {
                return Double.NaN;
            }
        }
        if (zzj(zzqoVar)) {
            throw new IllegalArgumentException(zzk(zzqoVar, "Illegal type given to numberEquivalent: "));
        }
        return Double.NaN;
    }

    public static double zzc(zzqo zzqoVar, zzqo zzqoVar2) throws NumberFormatException {
        u.b(zzqoVar != null);
        u.b(zzqoVar2 != null);
        double dZzb = zzb(zzqoVar);
        double dZzb2 = zzb(zzqoVar2);
        if (Double.isNaN(dZzb) || Double.isNaN(dZzb2)) {
            return Double.NaN;
        }
        if ((dZzb == Double.POSITIVE_INFINITY && dZzb2 == Double.NEGATIVE_INFINITY) || (dZzb == Double.NEGATIVE_INFINITY && dZzb2 == Double.POSITIVE_INFINITY)) {
            return Double.NaN;
        }
        return (!Double.isInfinite(dZzb) || Double.isInfinite(dZzb2)) ? (Double.isInfinite(dZzb) || !Double.isInfinite(dZzb2)) ? dZzb + dZzb2 : dZzb2 : dZzb;
    }

    /* JADX WARN: Failed to analyze thrown exceptions
    java.util.ConcurrentModificationException
    	at java.base/java.util.ArrayList$Itr.checkForComodification(ArrayList.java:1096)
    	at java.base/java.util.ArrayList$Itr.next(ArrayList.java:1050)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.processInstructions(MethodThrowsVisitor.java:118)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.visit(MethodThrowsVisitor.java:69)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.checkInsn(MethodThrowsVisitor.java:179)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.processInstructions(MethodThrowsVisitor.java:132)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.visit(MethodThrowsVisitor.java:69)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.checkInsn(MethodThrowsVisitor.java:179)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.processInstructions(MethodThrowsVisitor.java:132)
    	at jadx.core.dex.visitors.MethodThrowsVisitor.visit(MethodThrowsVisitor.java:69)
     */
    public static String zzd(zzqo zzqoVar) {
        u.b(zzqoVar != null);
        if (zzqoVar == zzqs.zze) {
            return "undefined";
        }
        if (zzqoVar == zzqs.zzd) {
            return "null";
        }
        if (zzqoVar instanceof zzqp) {
            return true != ((zzqp) zzqoVar).zzi().booleanValue() ? "false" : "true";
        }
        if (!(zzqoVar instanceof zzqq)) {
            if (zzqoVar instanceof zzqr) {
                zzjm zzjmVarZzi = ((zzqr) zzqoVar).zzi();
                if (zzjmVarZzi instanceof zzjl) {
                    return ((zzjl) zzjmVarZzi).zzb();
                }
            } else {
                if (zzqoVar instanceof zzqv) {
                    ArrayList arrayList = new ArrayList();
                    for (zzqo zzqoVar2 : ((zzqv) zzqoVar).zzk()) {
                        if (zzqoVar2 == zzqs.zzd || zzqoVar2 == zzqs.zze) {
                            arrayList.add("");
                        } else {
                            arrayList.add(zzd(zzqoVar2));
                        }
                    }
                    return TextUtils.join(",", arrayList);
                }
                if (zzqoVar instanceof zzqw) {
                    return "[object Object]";
                }
                if (zzqoVar instanceof zzqz) {
                    return ((zzqz) zzqoVar).zzk();
                }
            }
            throw new IllegalArgumentException(zzj(zzqoVar) ? zzk(zzqoVar, "Illegal type given to stringEquivalent: ") : "Unknown type in stringEquivalent.");
        }
        String string = Double.toString(((zzqq) zzqoVar).zzi().doubleValue());
        int iIndexOf = string.indexOf("E");
        if (iIndexOf <= 0) {
            if (string.endsWith(".0")) {
                string = string.substring(0, string.length() - 2);
                if (string.equals("-0")) {
                    return "0";
                }
            }
            return string;
        }
        int i = Integer.parseInt(string.substring(iIndexOf + 1, string.length()));
        if (i >= 0) {
            if (i >= 21) {
                return string.replace("E", "e+");
            }
            String strReplace = string.substring(0, iIndexOf).replace(".", "");
            int length = strReplace.length() - (strReplace.startsWith("-") ? 1 : 0);
            StringBuilder sb = new StringBuilder();
            int i2 = (i + 1) - length;
            if (i2 < 0) {
                int length2 = strReplace.length() + i2;
                sb.append(strReplace.substring(0, length2));
                sb.append(".");
                sb.append(strReplace.substring(length2, strReplace.length()));
            } else {
                sb.append(strReplace);
                while (i2 > 0) {
                    sb.append("0");
                    i2--;
                }
            }
            return sb.toString();
        }
        if (i <= -7) {
            return string.replace("E", "e");
        }
        String strReplace2 = string.substring(0, iIndexOf).replace(".", "");
        StringBuilder sb2 = new StringBuilder("0.");
        while (true) {
            i++;
            if (i >= 0) {
                sb2.append(strReplace2);
                return sb2.toString();
            }
            sb2.append("0");
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0076  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean zze(com.google.android.gms.internal.gtm.zzqo r12, com.google.android.gms.internal.gtm.zzqo r13) {
        /*
            Method dump skipped, instructions count: 446
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzjn.zze(com.google.android.gms.internal.gtm.zzqo, com.google.android.gms.internal.gtm.zzqo):boolean");
    }

    public static boolean zzf(zzqo zzqoVar, zzqo zzqoVar2) throws NumberFormatException {
        u.b(zzqoVar != null);
        u.b(zzqoVar2 != null);
        if (zzj(zzqoVar)) {
            throw new IllegalArgumentException(zzk(zzqoVar, "Illegal type given to abstractRelationalCompare: "));
        }
        if (zzj(zzqoVar2)) {
            throw new IllegalArgumentException(zzk(zzqoVar2, "Illegal type given to abstractRelationalCompare: "));
        }
        if ((zzqoVar instanceof zzqw) || (zzqoVar instanceof zzqv) || (zzqoVar instanceof zzqr)) {
            zzqoVar = new zzqz(zzd(zzqoVar));
        }
        if ((zzqoVar2 instanceof zzqw) || (zzqoVar2 instanceof zzqv) || (zzqoVar2 instanceof zzqr)) {
            zzqoVar2 = new zzqz(zzd(zzqoVar2));
        }
        if ((zzqoVar instanceof zzqz) && (zzqoVar2 instanceof zzqz)) {
            return ((zzqz) zzqoVar).zzk().compareTo(((zzqz) zzqoVar2).zzk()) < 0;
        }
        double dZzb = zzb(zzqoVar);
        double dZzb2 = zzb(zzqoVar2);
        if (Double.isNaN(dZzb) || Double.isNaN(dZzb2) || ((dZzb == 0.0d && dZzb2 == 0.0d) || ((dZzb == 0.0d && dZzb2 == 0.0d) || dZzb == Double.POSITIVE_INFINITY))) {
            return false;
        }
        if (dZzb2 == Double.POSITIVE_INFINITY) {
            return true;
        }
        if (dZzb2 == Double.NEGATIVE_INFINITY) {
            return false;
        }
        return dZzb == Double.NEGATIVE_INFINITY || Double.compare(dZzb, dZzb2) < 0;
    }

    public static boolean zzg(zzqo zzqoVar) {
        u.b(zzqoVar != null);
        if (zzqoVar == zzqs.zze || zzqoVar == zzqs.zzd) {
            return false;
        }
        if (zzqoVar instanceof zzqp) {
            return ((zzqp) zzqoVar).zzi().booleanValue();
        }
        if (zzqoVar instanceof zzqq) {
            zzqq zzqqVar = (zzqq) zzqoVar;
            if (zzqqVar.zzi().doubleValue() == 0.0d || zzqqVar.zzi().doubleValue() == 0.0d || Double.isNaN(zzqqVar.zzi().doubleValue())) {
                return false;
            }
        } else if (zzqoVar instanceof zzqz) {
            if (((zzqz) zzqoVar).zzk().isEmpty()) {
                return false;
            }
        } else if (zzj(zzqoVar)) {
            throw new IllegalArgumentException(zzk(zzqoVar, "Illegal type given to isTruthy: "));
        }
        return true;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:35:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean zzh(com.google.android.gms.internal.gtm.zzqo r7, com.google.android.gms.internal.gtm.zzqo r8) {
        /*
            r0 = 0
            r1 = 1
            if (r7 == 0) goto L6
            r2 = r1
            goto L7
        L6:
            r2 = r0
        L7:
            com.google.android.gms.common.internal.u.b(r2)
            if (r8 == 0) goto Le
            r2 = r1
            goto Lf
        Le:
            r2 = r0
        Lf:
            com.google.android.gms.common.internal.u.b(r2)
            boolean r2 = zzj(r7)
            java.lang.String r3 = "Illegal type given to strictEqualityCompare: "
            if (r2 != 0) goto Ld2
            boolean r2 = zzj(r8)
            if (r2 != 0) goto Lc8
            java.lang.String r2 = zzi(r7)
            java.lang.String r3 = zzi(r8)
            boolean r3 = r2.equals(r3)
            if (r3 != 0) goto L2f
            return r0
        L2f:
            int r3 = r2.hashCode()
            r4 = 2
            r5 = 3
            r6 = 4
            switch(r3) {
                case -1950496919: goto L62;
                case -1808118735: goto L58;
                case 2439591: goto L4e;
                case 965837104: goto L44;
                case 1729365000: goto L3a;
                default: goto L39;
            }
        L39:
            goto L6c
        L3a:
            java.lang.String r3 = "Boolean"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L6c
            r2 = r6
            goto L6d
        L44:
            java.lang.String r3 = "Undefined"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L6c
            r2 = r0
            goto L6d
        L4e:
            java.lang.String r3 = "Null"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L6c
            r2 = r1
            goto L6d
        L58:
            java.lang.String r3 = "String"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L6c
            r2 = r5
            goto L6d
        L62:
            java.lang.String r3 = "Number"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L6c
            r2 = r4
            goto L6d
        L6c:
            r2 = -1
        L6d:
            if (r2 == 0) goto Lc7
            if (r2 == r1) goto Lc7
            if (r2 == r4) goto La0
            if (r2 == r5) goto L8c
            if (r2 == r6) goto L7b
            if (r7 != r8) goto L7a
            return r1
        L7a:
            return r0
        L7b:
            com.google.android.gms.internal.gtm.zzqp r7 = (com.google.android.gms.internal.gtm.zzqp) r7
            java.lang.Boolean r7 = r7.zzi()
            com.google.android.gms.internal.gtm.zzqp r8 = (com.google.android.gms.internal.gtm.zzqp) r8
            java.lang.Boolean r8 = r8.zzi()
            boolean r7 = r7.equals(r8)
            return r7
        L8c:
            com.google.android.gms.internal.gtm.zzqz r7 = (com.google.android.gms.internal.gtm.zzqz) r7
            java.lang.String r7 = r7.zzk()
            com.google.android.gms.internal.gtm.zzqz r8 = (com.google.android.gms.internal.gtm.zzqz) r8
            java.lang.String r8 = r8.zzk()
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L9f
            return r1
        L9f:
            return r0
        La0:
            com.google.android.gms.internal.gtm.zzqq r7 = (com.google.android.gms.internal.gtm.zzqq) r7
            java.lang.Double r7 = r7.zzi()
            double r2 = r7.doubleValue()
            com.google.android.gms.internal.gtm.zzqq r8 = (com.google.android.gms.internal.gtm.zzqq) r8
            java.lang.Double r7 = r8.zzi()
            double r7 = r7.doubleValue()
            boolean r4 = java.lang.Double.isNaN(r2)
            if (r4 != 0) goto Lc6
            boolean r4 = java.lang.Double.isNaN(r7)
            if (r4 == 0) goto Lc1
            goto Lc6
        Lc1:
            int r7 = (r2 > r7 ? 1 : (r2 == r7 ? 0 : -1))
            if (r7 != 0) goto Lc6
            return r1
        Lc6:
            return r0
        Lc7:
            return r1
        Lc8:
            java.lang.IllegalArgumentException r7 = new java.lang.IllegalArgumentException
            java.lang.String r8 = zzk(r8, r3)
            r7.<init>(r8)
            throw r7
        Ld2:
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r7 = zzk(r7, r3)
            r8.<init>(r7)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzjn.zzh(com.google.android.gms.internal.gtm.zzqo, com.google.android.gms.internal.gtm.zzqo):boolean");
    }

    private static String zzi(zzqo zzqoVar) {
        return zzqoVar == zzqs.zze ? "Undefined" : zzqoVar == zzqs.zzd ? "Null" : zzqoVar instanceof zzqp ? "Boolean" : zzqoVar instanceof zzqq ? "Number" : zzqoVar instanceof zzqz ? "String" : "Object";
    }

    private static boolean zzj(zzqo zzqoVar) {
        if (zzqoVar instanceof zzqx) {
            return true;
        }
        return (!(zzqoVar instanceof zzqs) || zzqoVar == zzqs.zze || zzqoVar == zzqs.zzd) ? false : true;
    }

    private static /* synthetic */ String zzk(zzqo zzqoVar, String str) {
        return a.l(str, zzqoVar.zzc(), ".");
    }
}
