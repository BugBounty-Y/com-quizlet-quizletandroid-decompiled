package com.quizlet.shared.usecase.folderstudymaterials;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.media.MediaExtractor;
import android.media.MediaMetadataRetriever;
import android.os.SystemClock;
import android.text.TextUtils;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.I;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import com.bumptech.glide.load.resource.bitmap.E;
import com.google.android.gms.internal.measurement.C3036o3;
import com.google.android.gms.internal.measurement.C3080x3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.h4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.google.gson.internal.n;
import com.quizlet.data.model.F;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentSkipListMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class b implements f, androidx.preference.a, E, com.google.android.datatransport.runtime.time.a, com.google.android.gms.dynamite.b, r, n, com.google.zxing.b, com.quizlet.featuregate.contracts.features.a, com.quizlet.local.ormlite.util.c {
    public static b b;
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static com.perimeterx.mobile_sdk.doctor_app.model.g a(int i) {
        com.perimeterx.mobile_sdk.doctor_app.model.g gVar = i != 0 ? i != 1 ? null : com.perimeterx.mobile_sdk.doctor_app.model.g.e : com.perimeterx.mobile_sdk.doctor_app.model.g.d;
        if (gVar != null) {
            return gVar;
        }
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.f fVar2 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar.g;
        Intrinsics.d(fVar2);
        int iOrdinal = fVar2.ordinal();
        if (iOrdinal == 0) {
            switch (i) {
                case 2:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.g;
                case 3:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.h;
                case 4:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.i;
                case 5:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.j;
                case 6:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.k;
                case 7:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.l;
                case 8:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.r;
                case 9:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.s;
                case 10:
                    return com.perimeterx.mobile_sdk.doctor_app.model.g.s;
            }
        }
        if (iOrdinal != 1) {
            throw new NoWhenBranchMatchedException();
        }
        if (i == 2) {
            return com.perimeterx.mobile_sdk.doctor_app.model.g.m;
        }
        if (i == 3) {
            return com.perimeterx.mobile_sdk.doctor_app.model.g.n;
        }
        if (i == 4) {
            return com.perimeterx.mobile_sdk.doctor_app.model.g.o;
        }
        if (i == 5) {
            return com.perimeterx.mobile_sdk.doctor_app.model.g.p;
        }
        if (i == 8) {
            return com.perimeterx.mobile_sdk.doctor_app.model.g.t;
        }
        return null;
    }

    public static final com.ionspin.kotlin.bignum.decimal.b c(com.ionspin.kotlin.bignum.decimal.b bVar, com.ionspin.kotlin.bignum.decimal.b bVar2, com.ionspin.kotlin.bignum.decimal.b bVar3) {
        com.ionspin.kotlin.bignum.decimal.a aVar = com.ionspin.kotlin.bignum.decimal.a.f;
        if (bVar3 != null) {
            return bVar3;
        }
        if (bVar == null && bVar2 == null) {
            return new com.ionspin.kotlin.bignum.decimal.b(0L, (com.ionspin.kotlin.bignum.decimal.c) null, 7);
        }
        if (bVar == null && bVar2 != null) {
            return bVar2;
        }
        if (bVar2 == null && bVar != null) {
            return bVar;
        }
        Intrinsics.d(bVar);
        Intrinsics.d(bVar2);
        com.ionspin.kotlin.bignum.decimal.c cVar = bVar.b;
        com.ionspin.kotlin.bignum.decimal.c cVar2 = bVar2.b;
        if (cVar == cVar2) {
            return bVar.a >= bVar2.a ? bVar : bVar2;
        }
        throw new ArithmeticException("Different rounding modes! This: " + cVar + " Other: " + cVar2);
    }

    public static final com.ionspin.kotlin.bignum.decimal.a f(com.ionspin.kotlin.bignum.integer.c cVar, long j, com.ionspin.kotlin.bignum.decimal.b bVar) {
        com.ionspin.kotlin.bignum.decimal.a aVar = com.ionspin.kotlin.bignum.decimal.a.f;
        return bVar.d ? new com.ionspin.kotlin.bignum.decimal.a(cVar, j, 4) : r(cVar, j, bVar);
    }

    public static com.ionspin.kotlin.bignum.decimal.a i(double d) {
        String strSubstring;
        String strValueOf = String.valueOf(d);
        if (!StringsKt.F(strValueOf, '.', false) || StringsKt.F(strValueOf, 'E', true)) {
            com.ionspin.kotlin.bignum.decimal.a aVarQ = q(strValueOf);
            aVarQ.getClass();
            return aVarQ;
        }
        int iJ = StringsKt.J(strValueOf);
        while (true) {
            if (iJ < 0) {
                strSubstring = "";
                break;
            }
            if (strValueOf.charAt(iJ) != '0') {
                strSubstring = strValueOf.substring(0, iJ + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                break;
            }
            iJ--;
        }
        com.ionspin.kotlin.bignum.decimal.a aVarQ2 = q(strSubstring);
        aVarQ2.getClass();
        return aVarQ2;
    }

    public static com.ionspin.kotlin.bignum.decimal.a n(float f) {
        String strSubstring;
        String strValueOf = String.valueOf(f);
        if (!StringsKt.F(strValueOf, '.', false) || StringsKt.F(strValueOf, 'E', true)) {
            com.ionspin.kotlin.bignum.decimal.a aVarQ = q(strValueOf);
            aVarQ.getClass();
            return aVarQ;
        }
        int iJ = StringsKt.J(strValueOf);
        while (true) {
            if (iJ < 0) {
                strSubstring = "";
                break;
            }
            if (strValueOf.charAt(iJ) != '0') {
                strSubstring = strValueOf.substring(0, iJ + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                break;
            }
            iJ--;
        }
        com.ionspin.kotlin.bignum.decimal.a aVarQ2 = q(strSubstring);
        aVarQ2.getClass();
        return aVarQ2;
    }

    public static com.ionspin.kotlin.bignum.decimal.a o(int i) {
        com.ionspin.kotlin.bignum.integer.c cVar = new com.ionspin.kotlin.bignum.integer.c(i);
        return new com.ionspin.kotlin.bignum.decimal.a(cVar, cVar.j() - 1, (com.ionspin.kotlin.bignum.decimal.b) null);
    }

    public static F p(DBGroupSet local) {
        Intrinsics.checkNotNullParameter(local, "local");
        return new F(Long.valueOf(local.getLocalId()), local.getClassId(), local.getSetId(), local.getUserId(), local.getFolderId(), local.getCanEdit(), local.getTimestamp(), Boolean.valueOf(local.getDeleted()), Long.valueOf(local.getClientTimestamp()), local.getLastModified(), local.getDirty());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v3 */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r8v6 */
    public static com.ionspin.kotlin.bignum.decimal.a q(String floatingPointString) {
        int length;
        List listV;
        int i = 0;
        Intrinsics.checkNotNullParameter(floatingPointString, "floatingPointString");
        if (floatingPointString.length() == 0) {
            return com.ionspin.kotlin.bignum.decimal.a.f;
        }
        if (StringsKt.F(floatingPointString, 'E', true)) {
            if (StringsKt.F(floatingPointString, '.', false)) {
                listV = StringsKt.V(floatingPointString, new char[]{'.'});
            } else {
                List listV2 = StringsKt.V(floatingPointString, new char[]{'E', 'e'});
                listV = B.j((String) listV2.get(0), Intrinsics.k(listV2.get(1), "0E"));
            }
            if (listV.size() != 2) {
                throw new ArithmeticException(Intrinsics.k(floatingPointString, "Invalid (or unsupported) floating point number format: "));
            }
            int i2 = (floatingPointString.charAt(0) == '-' || floatingPointString.charAt(0) == '+') ? 1 : 0;
            boolean z = (i2 == 0 || floatingPointString.charAt(0) != '-') ? true : 2;
            String str = (String) listV.get(0);
            if (str == null) {
                throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
            }
            String strSubstring = str.substring(i2);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "(this as java.lang.String).substring(startIndex)");
            List listV3 = StringsKt.V((CharSequence) listV.get(1), new char[]{'E', 'e'});
            String str2 = (String) listV3.get(0);
            String str3 = (String) listV3.get(1);
            int i3 = (str3.charAt(0) == '-' || str3.charAt(0) == '+') ? 1 : 0;
            boolean z2 = str3.charAt(0) == '-' ? 2 : true;
            String strSubstring2 = str3.substring(i3);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "(this as java.lang.String).substring(startIndex)");
            long j = z2 ? Long.parseLong(strSubstring2, CharsKt.checkRadix(10)) : Long.parseLong(strSubstring2, CharsKt.checkRadix(10)) * (-1);
            int length2 = strSubstring.length();
            int i4 = 0;
            while (true) {
                if (i4 >= length2) {
                    i4 = -1;
                    break;
                }
                if (strSubstring.charAt(i4) != '0') {
                    break;
                }
                i4++;
            }
            if (i4 == -1) {
                i4 = 0;
            }
            int length3 = str2.length();
            while (true) {
                length3--;
                if (length3 < 0) {
                    length3 = -1;
                    break;
                }
                if (str2.charAt(length3) != '0') {
                    break;
                }
            }
            if (length3 == -1) {
                length3 = str2.length() - 1;
            }
            String strSubstring3 = strSubstring.substring(i4, strSubstring.length());
            Intrinsics.checkNotNullExpressionValue(strSubstring3, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            String strSubstring4 = str2.substring(0, length3 + 1);
            Intrinsics.checkNotNullExpressionValue(strSubstring4, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarR = c.r(Intrinsics.k(strSubstring4, strSubstring3));
            if ((Intrinsics.b(cVarR, com.ionspin.kotlin.bignum.integer.c.d) ? 3 : z) == 2) {
                cVarR = cVarR.i();
            }
            return new com.ionspin.kotlin.bignum.decimal.a(cVarR, (!Intrinsics.b(strSubstring3, "0") ? j + strSubstring3.length() : j - (strSubstring4.length() - cVarR.j())) - 1, (com.ionspin.kotlin.bignum.decimal.b) null);
        }
        if (!StringsKt.F(floatingPointString, '.', false)) {
            com.ionspin.kotlin.bignum.integer.base63.array.b bVar2 = com.ionspin.kotlin.bignum.integer.c.c;
            com.ionspin.kotlin.bignum.integer.c cVarR2 = c.r(floatingPointString);
            return new com.ionspin.kotlin.bignum.decimal.a(cVarR2, cVarR2.j() - 1, (com.ionspin.kotlin.bignum.decimal.b) null);
        }
        List listV4 = StringsKt.V(floatingPointString, new char[]{'.'});
        if (listV4.size() != 2) {
            throw new ArithmeticException(Intrinsics.k(floatingPointString, "Invalid (or unsupported) floating point number format: "));
        }
        int i5 = (floatingPointString.charAt(0) == '-' || floatingPointString.charAt(0) == '+') ? 1 : 0;
        boolean z3 = (i5 == 0 || floatingPointString.charAt(0) != '-') ? true : 2;
        String str4 = (String) listV4.get(0);
        if (str4 == null) {
            throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
        }
        String strSubstring5 = str4.substring(i5);
        Intrinsics.checkNotNullExpressionValue(strSubstring5, "(this as java.lang.String).substring(startIndex)");
        String str5 = (String) listV4.get(1);
        int length4 = strSubstring5.length();
        int i6 = 0;
        while (true) {
            if (i6 >= length4) {
                i6 = -1;
                break;
            }
            if (strSubstring5.charAt(i6) != '0') {
                break;
            }
            i6++;
        }
        if (i6 == -1) {
            i6 = 0;
        }
        int length5 = str5.length();
        while (true) {
            length5--;
            if (length5 < 0) {
                length5 = -1;
                break;
            }
            if (str5.charAt(length5) != '0') {
                break;
            }
        }
        if (length5 == -1) {
            length5 = str5.length() - 1;
        }
        String strSubstring6 = strSubstring5.substring(i6, strSubstring5.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring6, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        String strSubstring7 = str5.substring(0, length5 + 1);
        Intrinsics.checkNotNullExpressionValue(strSubstring7, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        com.ionspin.kotlin.bignum.integer.base63.array.b bVar3 = com.ionspin.kotlin.bignum.integer.c.c;
        com.ionspin.kotlin.bignum.integer.c cVarR3 = c.r(Intrinsics.k(strSubstring7, strSubstring6));
        if (strSubstring6.length() <= 0 || strSubstring6.charAt(0) == '0') {
            int length6 = strSubstring7.length();
            while (true) {
                if (i >= length6) {
                    i = -1;
                    break;
                }
                if (strSubstring7.charAt(i) != '0') {
                    break;
                }
                i++;
            }
            length = (-1) * (i + 1);
        } else {
            length = strSubstring6.length() - 1;
        }
        if ((Intrinsics.b(cVarR3, com.ionspin.kotlin.bignum.integer.c.d) ? 3 : z3) == 2) {
            cVarR3 = cVarR3.i();
        }
        return new com.ionspin.kotlin.bignum.decimal.a(cVarR3, length, (com.ionspin.kotlin.bignum.decimal.b) null);
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x01ed  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0259  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0262  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00f8  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x010d  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x01cf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.ionspin.kotlin.bignum.decimal.a r(com.ionspin.kotlin.bignum.integer.c r11, long r12, com.ionspin.kotlin.bignum.decimal.b r14) {
        /*
            Method dump skipped, instructions count: 780
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.b.r(com.ionspin.kotlin.bignum.integer.c, long, com.ionspin.kotlin.bignum.decimal.b):com.ionspin.kotlin.bignum.decimal.a");
    }

    public static I s(List list, float f, float f2, int i) {
        if ((i & 2) != 0) {
            f = 0.0f;
        }
        return new I(list, null, Q4.c(DefinitionKt.NO_Float_VALUE, f), Q4.c(DefinitionKt.NO_Float_VALUE, f2));
    }

    public static I t(Pair[] pairArr) {
        Pair[] pairArr2 = (Pair[]) Arrays.copyOf(pairArr, pairArr.length);
        long jC = Q4.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        long jC2 = Q4.c(DefinitionKt.NO_Float_VALUE, Float.POSITIVE_INFINITY);
        ArrayList arrayList = new ArrayList(pairArr2.length);
        for (Pair pair : pairArr2) {
            arrayList.add(new C0861v(((C0861v) pair.b).a));
        }
        ArrayList arrayList2 = new ArrayList(pairArr2.length);
        for (Pair pair2 : pairArr2) {
            arrayList2.add(Float.valueOf(((Number) pair2.a).floatValue()));
        }
        return new I(arrayList, arrayList2, jC, jC2);
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new ConcurrentSkipListMap();
    }

    @Override // androidx.preference.a
    public CharSequence b(Preference preference) {
        EditTextPreference editTextPreference = (EditTextPreference) preference;
        editTextPreference.getClass();
        if (TextUtils.isEmpty(null)) {
            return editTextPreference.a.getString(R.string.not_set);
        }
        return null;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void d(MediaExtractor mediaExtractor, Object obj) throws IOException {
        AssetFileDescriptor assetFileDescriptor = (AssetFileDescriptor) obj;
        mediaExtractor.setDataSource(assetFileDescriptor.getFileDescriptor(), assetFileDescriptor.getStartOffset(), assetFileDescriptor.getLength());
    }

    @Override // com.google.android.datatransport.runtime.time.a
    public long e() {
        return SystemClock.elapsedRealtime();
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return p((DBGroupSet) obj);
    }

    @Override // com.quizlet.featuregate.contracts.features.a
    public boolean isEnabled() {
        return false;
    }

    @Override // com.google.android.gms.dynamite.b
    public com.bumptech.glide.load.engine.cache.f k(Context context, String str, com.google.android.gms.dynamite.a aVar) {
        com.bumptech.glide.load.engine.cache.f fVar = new com.bumptech.glide.load.engine.cache.f();
        int iD = aVar.d(context, str, true);
        fVar.b = iD;
        if (iD != 0) {
            fVar.c = 1;
            return fVar;
        }
        int iE = aVar.e(context, str);
        fVar.a = iE;
        if (iE != 0) {
            fVar.c = -1;
        }
        return fVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0083  */
    @Override // com.google.zxing.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.zxing.common.b l(java.lang.String r20, int r21, int r22, int r23, java.util.EnumMap r24) {
        /*
            Method dump skipped, instructions count: 1134
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.b.l(java.lang.String, int, int, int, java.util.EnumMap):com.google.zxing.common.b");
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void m(MediaMetadataRetriever mediaMetadataRetriever, Object obj) throws IllegalArgumentException {
        AssetFileDescriptor assetFileDescriptor = (AssetFileDescriptor) obj;
        mediaMetadataRetriever.setDataSource(assetFileDescriptor.getFileDescriptor(), assetFileDescriptor.getStartOffset(), assetFileDescriptor.getLength());
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) h4.a.b();
                bool.getClass();
                return bool;
            case 11:
                Boolean bool2 = (Boolean) C3080x3.a.b();
                bool2.getClass();
                return bool2;
            case 12:
                Boolean bool3 = (Boolean) C3036o3.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list2 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.Q.b();
                l.getClass();
                return l;
            case 14:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.C.b();
                l2.getClass();
                return l2;
            case 15:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l3 = (Long) Q2.F.b();
                l3.getClass();
                return l3;
            case 16:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.f.b();
            default:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.u.b()).longValue());
        }
    }
}
