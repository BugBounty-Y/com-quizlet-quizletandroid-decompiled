package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zztw extends zzto {
    final transient Object[] zza;
    private final transient Object zzb;

    private zztw(Object obj, Object[] objArr, int i) {
        this.zzb = obj;
        this.zza = objArr;
    }

    /*  JADX ERROR: Types fix failed
        jadx.core.utils.exceptions.JadxRuntimeException: Several immutable types in one variable: [short[], byte[]], vars: [r1v2 ??, r1v6 ??, r1v4 ??, r1v8 ??, r1v9 ??]
        	at jadx.core.dex.visitors.InitCodeVariables.setCodeVarType(InitCodeVariables.java:107)
        	at jadx.core.dex.visitors.InitCodeVariables.setCodeVar(InitCodeVariables.java:83)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVar(InitCodeVariables.java:74)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVars(InitCodeVariables.java:48)
        	at jadx.core.dex.visitors.InitCodeVariables.rerun(InitCodeVariables.java:36)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryToFixIncompatiblePrimitives(FixTypesVisitor.java:695)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:91)
        */
    public static com.google.android.gms.internal.gtm.zztw zzg(int r16, java.lang.Object[] r17, com.google.android.gms.internal.gtm.zztn r18) {
        /*
            Method dump skipped, instructions count: 373
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zztw.zzg(int, java.lang.Object[], com.google.android.gms.internal.gtm.zztn):com.google.android.gms.internal.gtm.zztw");
    }

    @Override // com.google.android.gms.internal.gtm.zzto, java.util.Map
    public final Object get(Object obj) {
        Object obj2;
        if (obj == null) {
            obj2 = null;
        } else {
            Object[] objArr = this.zza;
            Object obj3 = this.zzb;
            if (obj3 instanceof byte[]) {
                byte[] bArr = (byte[]) obj3;
                int length = bArr.length - 1;
                int iZza = zzth.zza(obj.hashCode());
                while (true) {
                    int i = iZza & length;
                    int i2 = bArr[i] & 255;
                    if (i2 == 255) {
                        break;
                    }
                    if (obj.equals(objArr[i2])) {
                        obj2 = objArr[i2 ^ 1];
                        break;
                    }
                    iZza = i + 1;
                }
            } else if (obj3 instanceof short[]) {
                short[] sArr = (short[]) obj3;
                int length2 = sArr.length - 1;
                int iZza2 = zzth.zza(obj.hashCode());
                while (true) {
                    int i3 = iZza2 & length2;
                    char c = (char) sArr[i3];
                    if (c == 65535) {
                        break;
                    }
                    if (obj.equals(objArr[c])) {
                        obj2 = objArr[c ^ 1];
                        break;
                    }
                    iZza2 = i3 + 1;
                }
            } else {
                int[] iArr = (int[]) obj3;
                int length3 = iArr.length - 1;
                int iZza3 = zzth.zza(obj.hashCode());
                while (true) {
                    int i4 = iZza3 & length3;
                    int i5 = iArr[i4];
                    if (i5 == -1) {
                        break;
                    }
                    if (obj.equals(objArr[i5])) {
                        obj2 = objArr[i5 ^ 1];
                        break;
                    }
                    iZza3 = i4 + 1;
                }
            }
        }
        if (obj2 == null) {
            return null;
        }
        return obj2;
    }

    @Override // java.util.Map
    public final int size() {
        return 6;
    }

    @Override // com.google.android.gms.internal.gtm.zzto
    public final zzti zza() {
        return new zztv(this.zza, 1, 6);
    }

    @Override // com.google.android.gms.internal.gtm.zzto
    public final zztp zzd() {
        return new zztt(this, this.zza, 0, 6);
    }

    @Override // com.google.android.gms.internal.gtm.zzto
    public final zztp zze() {
        return new zztu(this, new zztv(this.zza, 0, 6));
    }
}
