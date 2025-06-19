package com.quizlet.shared.usecase.folderstudymaterials;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.graphics.PorterDuffColorFilter;
import android.media.MediaExtractor;
import android.media.MediaMetadataRetriever;
import android.os.Build;
import android.text.TextUtils;
import androidx.compose.animation.core.U0;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.graphics.F;
import androidx.fragment.app.Fragment;
import androidx.preference.ListPreference;
import androidx.preference.Preference;
import com.airbnb.lottie.parser.l;
import com.bumptech.glide.load.resource.bitmap.E;
import com.facebook.C1544a;
import com.facebook.o;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.T2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.play_billing.c2;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r;
import com.quizlet.data.model.C4127f1;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.quizlet.generated.enums.F1;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import kotlin.C;
import kotlin.D;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class c implements g, androidx.preference.a, com.google.android.datatransport.e, E, com.google.android.datatransport.runtime.time.a, com.google.android.gms.dynamite.b, r, com.google.firebase.crashlytics.internal.settings.c, com.google.zxing.b, com.perimeterx.mobile_sdk.doctor_app.state.d, com.quizlet.local.ormlite.util.c {
    public static c b;
    public static c c;
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    public static com.google.firebase.crashlytics.internal.settings.a f(com.onetrust.otpublishers.headless.Internal.Helper.h hVar) {
        boolean z = false;
        return new com.google.firebase.crashlytics.internal.settings.a(System.currentTimeMillis() + 3600000, new l(8, 11), new androidx.camera.camera2.internal.compat.workaround.c(true, z, z), 10.0d, 1.2d, 60);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.ionspin.kotlin.bignum.integer.c i(byte r11) {
        /*
            r0 = 1
            com.ionspin.kotlin.bignum.integer.c r1 = new com.ionspin.kotlin.bignum.integer.c
            com.ionspin.kotlin.bignum.integer.base63.array.b r2 = com.ionspin.kotlin.bignum.integer.c.c
            r2.getClass()
            int r2 = java.lang.Math.abs(r11)
            long r2 = (long) r2
            kotlin.C r4 = kotlin.D.b
            long[] r4 = new long[r0]
            r5 = 0
            r4[r5] = r2
            java.lang.Byte r2 = java.lang.Byte.valueOf(r11)
            java.lang.Class<java.lang.Byte> r3 = java.lang.Byte.class
            kotlin.jvm.internal.i r5 = kotlin.jvm.internal.K.a(r3)
            java.lang.Class r6 = java.lang.Long.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            r7 = 3
            r8 = 2
            if (r6 == 0) goto L46
            r11 = r2
            java.lang.Long r11 = (java.lang.Long) r11
            long r5 = r2.longValue()
            r9 = 0
            int r11 = (r5 > r9 ? 1 : (r5 == r9 ? 0 : -1))
            if (r11 >= 0) goto L3b
        L39:
            r0 = r8
            goto L91
        L3b:
            long r2 = r2.longValue()
            int r11 = (r2 > r9 ? 1 : (r2 == r9 ? 0 : -1))
            if (r11 <= 0) goto L44
            goto L91
        L44:
            r0 = r7
            goto L91
        L46:
            java.lang.Class r6 = java.lang.Integer.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            if (r6 == 0) goto L63
            r11 = r2
            java.lang.Integer r11 = (java.lang.Integer) r11
            int r11 = r2.intValue()
            if (r11 >= 0) goto L5c
            goto L39
        L5c:
            int r11 = r2.intValue()
            if (r11 <= 0) goto L44
            goto L91
        L63:
            java.lang.Class r6 = java.lang.Short.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            if (r6 == 0) goto L80
            r11 = r2
            java.lang.Short r11 = (java.lang.Short) r11
            short r11 = r2.shortValue()
            if (r11 >= 0) goto L79
            goto L39
        L79:
            short r11 = r2.shortValue()
            if (r11 <= 0) goto L44
            goto L91
        L80:
            java.lang.Class r2 = java.lang.Byte.TYPE
            kotlin.jvm.internal.i r2 = kotlin.jvm.internal.K.a(r2)
            boolean r2 = r5.equals(r2)
            if (r2 == 0) goto L95
            if (r11 >= 0) goto L8f
            goto L39
        L8f:
            if (r11 <= 0) goto L44
        L91:
            r1.<init>(r4, r0)
            return r1
        L95:
            java.lang.RuntimeException r11 = new java.lang.RuntimeException
            kotlin.jvm.internal.i r0 = kotlin.jvm.internal.K.a(r3)
            java.lang.String r1 = "Unsupported type "
            java.lang.String r0 = kotlin.jvm.internal.Intrinsics.k(r0, r1)
            r11.<init>(r0)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.c.i(byte):com.ionspin.kotlin.bignum.integer.c");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.ionspin.kotlin.bignum.integer.c j(short r11) {
        /*
            r0 = 1
            com.ionspin.kotlin.bignum.integer.c r1 = new com.ionspin.kotlin.bignum.integer.c
            com.ionspin.kotlin.bignum.integer.base63.array.b r2 = com.ionspin.kotlin.bignum.integer.c.c
            r2.getClass()
            int r2 = java.lang.Math.abs(r11)
            long r2 = (long) r2
            kotlin.C r4 = kotlin.D.b
            long[] r4 = new long[r0]
            r5 = 0
            r4[r5] = r2
            java.lang.Short r2 = java.lang.Short.valueOf(r11)
            java.lang.Class<java.lang.Short> r3 = java.lang.Short.class
            kotlin.jvm.internal.i r5 = kotlin.jvm.internal.K.a(r3)
            java.lang.Class r6 = java.lang.Long.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            r7 = 3
            r8 = 2
            if (r6 == 0) goto L46
            r11 = r2
            java.lang.Long r11 = (java.lang.Long) r11
            long r5 = r2.longValue()
            r9 = 0
            int r11 = (r5 > r9 ? 1 : (r5 == r9 ? 0 : -1))
            if (r11 >= 0) goto L3b
        L39:
            r0 = r8
            goto L91
        L3b:
            long r2 = r2.longValue()
            int r11 = (r2 > r9 ? 1 : (r2 == r9 ? 0 : -1))
            if (r11 <= 0) goto L44
            goto L91
        L44:
            r0 = r7
            goto L91
        L46:
            java.lang.Class r6 = java.lang.Integer.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            if (r6 == 0) goto L63
            r11 = r2
            java.lang.Integer r11 = (java.lang.Integer) r11
            int r11 = r2.intValue()
            if (r11 >= 0) goto L5c
            goto L39
        L5c:
            int r11 = r2.intValue()
            if (r11 <= 0) goto L44
            goto L91
        L63:
            java.lang.Class r6 = java.lang.Short.TYPE
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            boolean r6 = r5.equals(r6)
            if (r6 == 0) goto L75
            if (r11 >= 0) goto L72
            goto L39
        L72:
            if (r11 <= 0) goto L44
            goto L91
        L75:
            java.lang.Class r11 = java.lang.Byte.TYPE
            kotlin.jvm.internal.i r11 = kotlin.jvm.internal.K.a(r11)
            boolean r11 = r5.equals(r11)
            if (r11 == 0) goto L95
            r11 = r2
            java.lang.Byte r11 = (java.lang.Byte) r11
            byte r11 = r2.byteValue()
            if (r11 >= 0) goto L8b
            goto L39
        L8b:
            byte r11 = r2.byteValue()
            if (r11 <= 0) goto L44
        L91:
            r1.<init>(r4, r0)
            return r1
        L95:
            java.lang.RuntimeException r11 = new java.lang.RuntimeException
            kotlin.jvm.internal.i r0 = kotlin.jvm.internal.K.a(r3)
            java.lang.String r1 = "Unsupported type "
            java.lang.String r0 = kotlin.jvm.internal.Intrinsics.k(r0, r1)
            r11.<init>(r0)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.c.j(short):com.ionspin.kotlin.bignum.integer.c");
    }

    public static com.ionspin.kotlin.bignum.integer.c n(long j) {
        com.ionspin.kotlin.bignum.integer.c.c.getClass();
        long j2 = Long.MIN_VALUE & j;
        C c2 = D.b;
        return new com.ionspin.kotlin.bignum.integer.c(j2 != 0 ? new long[]{j & Long.MAX_VALUE, 1} : new long[]{j}, 1);
    }

    public static C4127f1 q(DBProgressReset local) {
        Intrinsics.checkNotNullParameter(local, "local");
        long personId = local.getPersonId();
        long containerId = local.getContainerId();
        F1 f1 = G1.Companion;
        short containerType = local.getContainerType();
        f1.getClass();
        return new C4127f1(personId, containerId, F1.a(containerType), Long.valueOf(local.getResetTimeSec()));
    }

    public static com.ionspin.kotlin.bignum.integer.c r(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        if (StringsKt.F(string, '.', false)) {
            com.ionspin.kotlin.bignum.decimal.a aVar = com.ionspin.kotlin.bignum.decimal.a.f;
            Intrinsics.checkNotNullParameter(string, "string");
            com.ionspin.kotlin.bignum.decimal.a aVarQ = b.q(string);
            aVarQ.getClass();
            com.ionspin.kotlin.bignum.decimal.a other = b.r(aVarQ.b, aVarQ.c, new com.ionspin.kotlin.bignum.decimal.b(aVarQ.c + 1, com.ionspin.kotlin.bignum.decimal.c.a, 4));
            Intrinsics.checkNotNullParameter(other, "other");
            if (aVarQ.e(other, aVarQ.c(other)).compareTo(0) <= 0) {
                return aVarQ.f();
            }
            throw new NumberFormatException("Supplied string is decimal, which cannot be converted to BigInteger without precision loss.");
        }
        if (string.charAt(0) != '-' && string.charAt(0) != '+') {
            return (string.length() == 1 && string.charAt(0) == '0') ? com.ionspin.kotlin.bignum.integer.c.d : new com.ionspin.kotlin.bignum.integer.c(com.ionspin.kotlin.bignum.integer.c.c.p(string), 1);
        }
        if (string.length() == 1) {
            throw new NumberFormatException(Intrinsics.k(string, "Invalid big integer: "));
        }
        int i = string.charAt(0) == '-' ? 2 : 1;
        if (string.length() == 2 && string.charAt(1) == '0') {
            return com.ionspin.kotlin.bignum.integer.c.d;
        }
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar = com.ionspin.kotlin.bignum.integer.c.c;
        String strSubstring = string.substring(1, string.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        return new com.ionspin.kotlin.bignum.integer.c(bVar.p(strSubstring), i);
    }

    public static C0853m s(long j) {
        return new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(F.A(j), F.E(5)));
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return com.perimeterx.mobile_sdk.doctor_app.state.a.c;
    }

    @Override // com.google.android.datatransport.e
    public Object apply(Object obj) {
        return ((c2) obj).b();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new com.perimeterx.mobile_sdk.doctor_app.ui.f();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return new ArrayList();
    }

    @Override // com.google.android.datatransport.runtime.time.a
    public long e() {
        return System.currentTimeMillis();
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return q((DBProgressReset) obj);
    }

    @Override // com.google.android.gms.dynamite.b
    public com.bumptech.glide.load.engine.cache.f k(Context context, String str, com.google.android.gms.dynamite.a aVar) {
        com.bumptech.glide.load.engine.cache.f fVar = new com.bumptech.glide.load.engine.cache.f();
        int iE = aVar.e(context, str);
        fVar.a = iE;
        if (iE != 0) {
            fVar.c = -1;
            return fVar;
        }
        int iD = aVar.d(context, str, true);
        fVar.b = iD;
        if (iD != 0) {
            fVar.c = 1;
        }
        return fVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v25, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v32 */
    /* JADX WARN: Type inference failed for: r3v50 */
    @Override // com.google.zxing.b
    public com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) {
        int i4;
        int i5;
        int i6;
        com.google.zxing.datamatrix.encoder.e eVar;
        int i7;
        char c2;
        int i8;
        char c3;
        int i9;
        int i10;
        byte[] bArr;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        com.google.zxing.common.b bVar;
        int i17;
        int i18;
        byte[] bArr2;
        boolean z;
        int i19;
        int i20 = 0;
        int i21 = 20;
        int i22 = 2;
        int i23 = 1;
        if (str.isEmpty()) {
            throw new IllegalArgumentException("Found empty contents");
        }
        if (i != 6) {
            throw new IllegalArgumentException("Can only encode DATA_MATRIX, but got ".concat(Z.t(i)));
        }
        if (i2 < 0 || i3 < 0) {
            throw new IllegalArgumentException("Requested dimensions can't be negative: " + i2 + 'x' + i3);
        }
        com.google.zxing.datamatrix.encoder.f fVar = com.google.zxing.datamatrix.encoder.f.a;
        com.google.zxing.datamatrix.encoder.f fVar2 = (com.google.zxing.datamatrix.encoder.f) enumMap.get(com.google.zxing.a.c);
        if (fVar2 != null) {
            fVar = fVar2;
        }
        if (enumMap.get(com.google.zxing.a.d) != null) {
            throw new ClassCastException();
        }
        if (enumMap.get(com.google.zxing.a.e) != null) {
            throw new ClassCastException();
        }
        int i24 = 3;
        int i25 = 0;
        com.google.zxing.datamatrix.encoder.b[] bVarArr = {new d(i21), new com.quizlet.shared.usecase.studiableMetadata.a(i21), new com.google.zxing.datamatrix.encoder.g(i20), new com.google.zxing.datamatrix.encoder.g(i23), new retrofit2.adapter.rxjava3.d(i21), new com.quizlet.shared.usecase.srs.a(i21)};
        com.google.zxing.datamatrix.encoder.c cVar = new com.google.zxing.datamatrix.encoder.c(str);
        cVar.b = fVar;
        if (str.startsWith("[)>\u001e05\u001d") && str.endsWith("\u001e\u0004")) {
            cVar.d((char) 236);
            cVar.g = 2;
            cVar.d += 7;
        } else if (str.startsWith("[)>\u001e06\u001d") && str.endsWith("\u001e\u0004")) {
            cVar.d((char) 237);
            cVar.g = 2;
            cVar.d += 7;
        }
        int i26 = 0;
        while (cVar.b()) {
            bVarArr[i26].c(cVar);
            int i27 = cVar.e;
            if (i27 >= 0) {
                cVar.e = -1;
                i26 = i27;
            }
        }
        StringBuilder sb = cVar.c;
        int length = sb.length();
        cVar.c(sb.length());
        int i28 = cVar.f.b;
        if (length < i28 && i26 != 0 && i26 != 5 && i26 != 4) {
            cVar.d((char) 254);
        }
        if (sb.length() < i28) {
            sb.append((char) 129);
        }
        while (sb.length() < i28) {
            int length2 = ((sb.length() + 1) * 149) % 253;
            int i29 = length2 + 130;
            if (i29 > 254) {
                i29 = length2 - 124;
            }
            sb.append((char) i29);
        }
        String string = sb.toString();
        com.google.zxing.datamatrix.encoder.e eVarE = com.google.zxing.datamatrix.encoder.e.e(string.length(), fVar);
        int[] iArr = com.google.zxing.datamatrix.encoder.d.a;
        int length3 = string.length();
        int i30 = eVarE.b;
        if (length3 != i30) {
            throw new IllegalArgumentException("The number of codewords does not match the selected symbol");
        }
        int i31 = eVarE.c;
        StringBuilder sb2 = new StringBuilder(i30 + i31);
        sb2.append(string);
        int iC = eVarE.c();
        if (iC == 1) {
            sb2.append(com.google.zxing.datamatrix.encoder.d.a(i31, string));
        } else {
            sb2.setLength(sb2.capacity());
            int[] iArr2 = new int[iC];
            int[] iArr3 = new int[iC];
            int[] iArr4 = new int[iC];
            int i32 = 0;
            while (i32 < iC) {
                int i33 = i32 + 1;
                iArr2[i32] = eVarE.a(i33);
                iArr3[i32] = eVarE.h;
                iArr4[i32] = 0;
                if (i32 > 0) {
                    iArr4[i32] = iArr4[i32 - 1] + iArr2[i32];
                }
                i32 = i33;
            }
            for (int i34 = 0; i34 < iC; i34++) {
                StringBuilder sb3 = new StringBuilder(iArr2[i34]);
                for (int i35 = i34; i35 < i30; i35 += iC) {
                    sb3.append(string.charAt(i35));
                }
                String strA = com.google.zxing.datamatrix.encoder.d.a(iArr3[i34], sb3.toString());
                int i36 = i34;
                int i37 = 0;
                while (i36 < iArr3[i34] * iC) {
                    sb2.setCharAt(i30 + i36, strA.charAt(i37));
                    i36 += iC;
                    i37++;
                }
            }
        }
        String string2 = sb2.toString();
        int iB = eVarE.b();
        int i38 = eVarE.d;
        int iD = eVarE.d();
        int i39 = eVarE.e;
        androidx.compose.ui.text.android.selection.f fVar3 = new androidx.compose.ui.text.android.selection.f(string2, iB * i38, iD * i39);
        int i40 = 4;
        int i41 = 0;
        int i42 = 0;
        while (true) {
            i4 = fVar3.c;
            i5 = fVar3.b;
            if (i40 == i5 && i42 == 0) {
                int i43 = i5 - 1;
                int i44 = i25;
                fVar3.j(i43, i44, i41, 1);
                fVar3.j(i43, 1, i41, i22);
                fVar3.j(i43, i22, i41, i24);
                fVar3.j(i44, i4 - 2, i41, 4);
                int i45 = i4 - 1;
                fVar3.j(i44, i45, i41, 5);
                fVar3.j(1, i45, i41, 6);
                fVar3.j(i22, i45, i41, 7);
                fVar3.j(3, i45, i41, 8);
                i41++;
            }
            i6 = i5 - 2;
            if (i40 == i6 && i42 == 0 && i4 % 4 != 0) {
                i8 = 1;
                eVar = eVarE;
                fVar3.j(i5 - 3, 0, i41, 1);
                fVar3.j(i6, 0, i41, i22);
                i7 = i22;
                fVar3.j(i5 - 1, 0, i41, 3);
                fVar3.j(0, i4 - 4, i41, 4);
                fVar3.j(0, i4 - 3, i41, 5);
                fVar3.j(0, i4 - 2, i41, 6);
                int i46 = i4 - 1;
                fVar3.j(0, i46, i41, 7);
                c2 = '\b';
                fVar3.j(1, i46, i41, 8);
                i41++;
            } else {
                eVar = eVarE;
                i7 = i22;
                c2 = '\b';
                i8 = 1;
            }
            if (i40 != i6 || i42 != 0) {
                c3 = c2;
                i9 = i7;
            } else if (i4 % 8 == 4) {
                fVar3.j(i5 - 3, 0, i41, i8);
                fVar3.j(i6, 0, i41, i7);
                fVar3.j(i5 - 1, 0, i41, 3);
                fVar3.j(0, i4 - 2, i41, 4);
                int i47 = i4 - 1;
                fVar3.j(0, i47, i41, 5);
                fVar3.j(i8, i47, i41, 6);
                i9 = i7;
                fVar3.j(i9, i47, i41, 7);
                c3 = '\b';
                fVar3.j(3, i47, i41, 8);
                i41++;
            } else {
                i9 = i7;
                c3 = '\b';
            }
            if (i40 == i5 + 4 && i42 == i9 && i4 % 8 == 0) {
                int i48 = i5 - 1;
                fVar3.j(i48, 0, i41, 1);
                int i49 = i4 - 1;
                fVar3.j(i48, i49, i41, i9);
                int i50 = i4 - 3;
                fVar3.j(0, i50, i41, 3);
                int i51 = i4 - 2;
                fVar3.j(0, i51, i41, 4);
                fVar3.j(0, i49, i41, 5);
                fVar3.j(1, i50, i41, 6);
                fVar3.j(1, i51, i41, 7);
                fVar3.j(1, i49, i41, 8);
                i10 = i40;
                i41++;
                while (true) {
                    bArr = (byte[]) fVar3.e;
                    if (i10 < i5) {
                        fVar3.n(i10, i42, i41);
                        i41++;
                    }
                    i11 = i10 - 2;
                    i12 = i42 + 2;
                    if (i11 < 0) {
                        break;
                    }
                    break;
                    break;
                    i10 = i11;
                    i42 = i12;
                }
                i13 = i10 - 1;
                i14 = i42 + 5;
                while (true) {
                    if (i13 >= 0) {
                        fVar3.n(i13, i14, i41);
                        i41++;
                    }
                    i15 = i13 + 2;
                    i16 = i14 - 2;
                    if (i15 >= i5) {
                        break;
                    }
                    break;
                    break;
                    i13 = i15;
                    i14 = i16;
                }
                i40 = i13 + 5;
                i42 = i14 - 1;
                if (i40 < i5) {
                }
                i25 = 0;
                eVarE = eVar;
                i22 = 2;
                i24 = 3;
            } else {
                int i52 = i40;
                i10 = i52;
                while (true) {
                    bArr = (byte[]) fVar3.e;
                    if (i10 < i5 && i42 >= 0 && bArr[(i10 * i4) + i42] < 0) {
                        fVar3.n(i10, i42, i41);
                        i41++;
                    }
                    i11 = i10 - 2;
                    i12 = i42 + 2;
                    if (i11 < 0 || i12 >= i4) {
                        break;
                    }
                    i10 = i11;
                    i42 = i12;
                }
                i13 = i10 - 1;
                i14 = i42 + 5;
                while (true) {
                    if (i13 >= 0 && i14 < i4 && bArr[(i13 * i4) + i14] < 0) {
                        fVar3.n(i13, i14, i41);
                        i41++;
                    }
                    i15 = i13 + 2;
                    i16 = i14 - 2;
                    if (i15 >= i5 || i16 < 0) {
                        break;
                    }
                    i13 = i15;
                    i14 = i16;
                }
                i40 = i13 + 5;
                i42 = i14 - 1;
                if (i40 < i5 && i42 >= i4) {
                    break;
                }
                i25 = 0;
                eVarE = eVar;
                i22 = 2;
                i24 = 3;
            }
        }
        int i53 = i4 - 1;
        int i54 = i5 - 1;
        if (bArr[(i54 * i4) + i53] < 0) {
            int i55 = (i54 * i4) + i53;
            byte b2 = (byte) 1;
            bArr[i55] = b2;
            bArr[(i6 * i4) + (i4 - 2)] = b2;
        }
        int iB2 = eVar.b() * i38;
        int iD2 = eVar.d() * i39;
        U0 u0 = new U0((eVar.b() * i38) + (eVar.b() << 1), (eVar.d() * i39) + (eVar.d() << 1), 6);
        int i56 = 0;
        int i57 = 0;
        while (i57 < iD2) {
            int i58 = i57 % i39;
            if (i58 == 0) {
                int i59 = 0;
                int i60 = 0;
                while (true) {
                    bArr2 = bArr;
                    z = true;
                    if (i59 >= (eVar.b() * i38) + (eVar.b() << 1)) {
                        break;
                    }
                    u0.r(i60, i56, i59 % 2 == 0);
                    i60++;
                    i59++;
                    bArr = bArr2;
                }
                i56++;
            } else {
                bArr2 = bArr;
                z = true;
            }
            int i61 = 0;
            int i62 = 0;
            ?? r3 = z;
            while (i61 < iB2) {
                int i63 = i61 % i38;
                if (i63 == 0) {
                    u0.r(i62, i56, r3);
                    i62 += r3;
                }
                u0.r(i62, i56, bArr2[(i57 * i4) + i61] == r3 ? r3 : false);
                int i64 = i62 + 1;
                boolean z2 = r3;
                if (i63 == i38 - 1) {
                    u0.r(i64, i56, i57 % 2 == 0 ? z2 : false);
                    i62 += 2;
                } else {
                    i62 = i64;
                }
                i61++;
                r3 = z2;
            }
            boolean z3 = r3;
            int i65 = i56 + 1;
            if (i58 == i39 - 1) {
                int i66 = 0;
                for (int i67 = 0; i67 < (eVar.b() * i38) + (eVar.b() << 1); i67 += z3 ? 1 : 0) {
                    u0.r(i66, i65, z3);
                    i66 += z3 ? 1 : 0;
                }
                i19 = z3 ? 1 : 0;
                i56 += 2;
            } else {
                i19 = z3 ? 1 : 0;
                i56 = i65;
            }
            i57 += i19;
            bArr = bArr2;
        }
        int i68 = u0.b;
        int iMax = Math.max(i2, i68);
        int i69 = u0.c;
        int iMax2 = Math.max(i3, i69);
        int iMin = Math.min(iMax / i68, iMax2 / i69);
        int i70 = (iMax - (i68 * iMin)) / 2;
        int i71 = (iMax2 - (i69 * iMin)) / 2;
        if (i3 < i69 || i2 < i68) {
            bVar = new com.google.zxing.common.b(i68, i69);
            i17 = 0;
            i18 = 0;
        } else {
            bVar = new com.google.zxing.common.b(i2, i3);
            i17 = i70;
            i18 = i71;
        }
        int[] iArr5 = bVar.d;
        int length4 = iArr5.length;
        for (int i72 = 0; i72 < length4; i72++) {
            iArr5[i72] = 0;
        }
        int i73 = i18;
        int i74 = 0;
        while (i74 < i69) {
            int i75 = i17;
            int i76 = 0;
            while (i76 < i68) {
                if (u0.o(i76, i74) == 1) {
                    bVar.d(i75, i73, iMin, iMin);
                }
                i76++;
                i75 += iMin;
            }
            i74++;
            i73 += iMin;
        }
        return bVar;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void m(MediaMetadataRetriever mediaMetadataRetriever, Object obj) throws IllegalArgumentException {
        mediaMetadataRetriever.setDataSource(new com.bumptech.glide.load.resource.bitmap.D((ByteBuffer) obj));
    }

    public com.facebook.f o() {
        com.facebook.f fVar;
        com.facebook.f fVar2 = com.facebook.f.g;
        if (fVar2 != null) {
            return fVar2;
        }
        synchronized (this) {
            fVar = com.facebook.f.g;
            if (fVar == null) {
                androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a(o.a());
                Intrinsics.checkNotNullExpressionValue(bVarA, "getInstance(applicationContext)");
                com.facebook.f fVar3 = new com.facebook.f(bVarA, new C1544a());
                com.facebook.f.g = fVar3;
                fVar = fVar3;
            }
        }
        return fVar;
    }

    public Signature[] p(PackageManager packageManager, String str) {
        return packageManager.getPackageInfo(str, 64).signatures;
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                return Integer.valueOf((int) ((Long) T2.a.b()).longValue());
            case 11:
                List list2 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool = (Boolean) G3.f.b();
                bool.getClass();
                return bool;
            case 12:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.i0.b()).longValue());
            case 13:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.R.b();
                l.getClass();
                return l;
            case 14:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.h.b();
                l2.getClass();
                return l2;
            case 15:
                List list6 = AbstractC3893t.a;
                B3.b.get();
                Boolean bool2 = (Boolean) D3.a.b();
                bool2.getClass();
                return bool2;
            case 16:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.v.b()).longValue());
            default:
                List list8 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.t.b()).longValue());
        }
    }

    @Override // com.google.firebase.crashlytics.internal.settings.c
    public com.google.firebase.crashlytics.internal.settings.a a(com.onetrust.otpublishers.headless.Internal.Helper.h hVar, JSONObject jSONObject) {
        return f(hVar);
    }

    @Override // androidx.preference.a
    public CharSequence b(Preference preference) {
        ListPreference listPreference = (ListPreference) preference;
        listPreference.getClass();
        if (TextUtils.isEmpty(null)) {
            return listPreference.a.getString(R.string.not_set);
        }
        return null;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void d(MediaExtractor mediaExtractor, Object obj) throws IOException {
        mediaExtractor.setDataSource(new com.bumptech.glide.load.resource.bitmap.D((ByteBuffer) obj));
    }
}
