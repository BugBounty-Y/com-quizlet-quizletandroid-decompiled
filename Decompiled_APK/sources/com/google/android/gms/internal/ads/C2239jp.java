package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.jp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2239jp implements CC {
    public final /* synthetic */ int a;
    public final com.android.billingclient.api.s b;

    public /* synthetic */ C2239jp(com.android.billingclient.api.s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0090  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Integer a() {
        /*
            r12 = this;
            com.android.billingclient.api.s r0 = r12.b
            java.lang.Object r0 = r0.c
            com.google.android.gms.internal.ads.zzbvl r0 = (com.google.android.gms.internal.ads.zzbvl) r0
            android.os.Bundle r0 = r0.a
            java.lang.String r1 = "extras"
            android.os.Bundle r0 = r0.getBundle(r1)
            r1 = -1
            if (r0 != 0) goto L13
            goto La6
        L13:
            boolean r2 = r0.isEmpty()
            if (r2 == 0) goto L1b
            goto La6
        L1b:
            java.lang.String r2 = "query_info_type"
            java.lang.String r3 = ""
            java.lang.String r0 = r0.getString(r2, r3)
            int r2 = r0.hashCode()
            r3 = 0
            r4 = 1
            r5 = 2
            r6 = 3
            r7 = 4
            r8 = 5
            r9 = 6
            r10 = 7
            r11 = 8
            switch(r2) {
                case 1743582862: goto L86;
                case 1743582863: goto L7c;
                case 1743582864: goto L72;
                case 1743582865: goto L68;
                case 1743582866: goto L5e;
                case 1743582867: goto L54;
                case 1743582868: goto L4a;
                case 1743582869: goto L40;
                case 1743582870: goto L36;
                default: goto L34;
            }
        L34:
            goto L90
        L36:
            java.lang.String r2 = "requester_type_8"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r11
            goto L91
        L40:
            java.lang.String r2 = "requester_type_7"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r10
            goto L91
        L4a:
            java.lang.String r2 = "requester_type_6"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r9
            goto L91
        L54:
            java.lang.String r2 = "requester_type_5"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r8
            goto L91
        L5e:
            java.lang.String r2 = "requester_type_4"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r7
            goto L91
        L68:
            java.lang.String r2 = "requester_type_3"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r6
            goto L91
        L72:
            java.lang.String r2 = "requester_type_2"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r5
            goto L91
        L7c:
            java.lang.String r2 = "requester_type_1"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r4
            goto L91
        L86:
            java.lang.String r2 = "requester_type_0"
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L90
            r0 = r3
            goto L91
        L90:
            r0 = r1
        L91:
            switch(r0) {
                case 0: goto La5;
                case 1: goto La3;
                case 2: goto La1;
                case 3: goto L9f;
                case 4: goto L9d;
                case 5: goto L9b;
                case 6: goto L99;
                case 7: goto L97;
                case 8: goto L95;
                default: goto L94;
            }
        L94:
            goto La6
        L95:
            r1 = r11
            goto La6
        L97:
            r1 = r10
            goto La6
        L99:
            r1 = r9
            goto La6
        L9b:
            r1 = r8
            goto La6
        L9d:
            r1 = r7
            goto La6
        L9f:
            r1 = r6
            goto La6
        La1:
            r1 = r5
            goto La6
        La3:
            r1 = r4
            goto La6
        La5:
            r1 = r3
        La6:
            java.lang.Integer r0 = java.lang.Integer.valueOf(r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2239jp.a():java.lang.Integer");
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                String str = ((zzbvl) this.b.c).d;
                AbstractC1981ds.s(str);
                return str;
            case 1:
                return Integer.valueOf(this.b.b);
            case 2:
                return Boolean.valueOf(((zzbvl) this.b.c).l);
            case 3:
                return Boolean.valueOf(((zzbvl) this.b.c).a.getBoolean("is_gbid"));
            case 4:
                return Boolean.valueOf(((zzbvl) this.b.c).k);
            case 5:
                String str2 = ((zzbvl) this.b.c).h;
                AbstractC1981ds.s(str2);
                return str2;
            case 6:
                return a();
            default:
                return Integer.valueOf(((zzbvl) this.b.c).o);
        }
    }
}
