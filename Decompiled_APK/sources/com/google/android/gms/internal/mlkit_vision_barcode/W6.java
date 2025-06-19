package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;
import io.ktor.http.BadContentTypeFormatException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class W6 {
    public static final /* synthetic */ int a = 0;

    public static androidx.emoji2.text.u a(Context context) {
        ProviderInfo providerInfo;
        androidx.core.provider.d dVar;
        ApplicationInfo applicationInfo;
        com.quizlet.shared.usecase.folderstudymaterials.c cVar = Build.VERSION.SDK_INT >= 28 ? new androidx.emoji2.text.c(3) : new com.quizlet.shared.usecase.folderstudymaterials.c(3);
        PackageManager packageManager = context.getPackageManager();
        AbstractC3242q6.g(packageManager, "Package manager required to locate emoji font provider");
        Iterator<ResolveInfo> it2 = packageManager.queryIntentContentProviders(new Intent("androidx.content.action.LOAD_EMOJI_FONT"), 0).iterator();
        while (true) {
            if (!it2.hasNext()) {
                providerInfo = null;
                break;
            }
            providerInfo = it2.next().providerInfo;
            if (providerInfo != null && (applicationInfo = providerInfo.applicationInfo) != null && (applicationInfo.flags & 1) == 1) {
                break;
            }
        }
        if (providerInfo == null) {
            dVar = null;
        } else {
            try {
                String str = providerInfo.authority;
                String str2 = providerInfo.packageName;
                Signature[] signatureArrP = cVar.p(packageManager, str2);
                ArrayList arrayList = new ArrayList();
                for (Signature signature : signatureArrP) {
                    arrayList.add(signature.toByteArray());
                }
                dVar = new androidx.core.provider.d(str, str2, "emojicompat-emoji-font", Collections.singletonList(arrayList));
            } catch (PackageManager.NameNotFoundException e) {
                Log.wtf("emoji2.text.DefaultEmojiConfig", e);
            }
        }
        if (dVar == null) {
            return null;
        }
        return new androidx.emoji2.text.u(new androidx.emoji2.text.t(context, dVar));
    }

    public static io.ktor.http.d b(String value) throws BadContentTypeFormatException {
        int i;
        Pair pair;
        Pair pair2;
        Intrinsics.checkNotNullParameter(value, "value");
        if (StringsKt.O(value)) {
            return io.ktor.http.d.f;
        }
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new io.ktor.client.plugins.api.b(4));
        for (int i2 = 0; i2 <= StringsKt.J(value); i2 = i) {
            kotlin.k kVarA2 = kotlin.l.a(kotlin.m.c, new io.ktor.client.plugins.api.b(5));
            Integer numValueOf = null;
            i = i2;
            while (true) {
                if (i <= StringsKt.J(value)) {
                    char cCharAt = value.charAt(i);
                    if (cCharAt == ',') {
                        ((ArrayList) kVarA.getValue()).add(new io.ktor.http.g(Y6.d(i2, numValueOf != null ? numValueOf.intValue() : i, value), kVarA2.isInitialized() ? (List) kVarA2.getValue() : kotlin.collections.K.a));
                        i++;
                    } else if (cCharAt != ';') {
                        i++;
                    } else {
                        if (numValueOf == null) {
                            numValueOf = Integer.valueOf(i);
                        }
                        int i3 = i + 1;
                        int i4 = i3;
                        while (i4 <= StringsKt.J(value)) {
                            char cCharAt2 = value.charAt(i4);
                            if (cCharAt2 == ',' || cCharAt2 == ';') {
                                Y6.c(kVarA2, value, i3, i4, "");
                                break;
                            }
                            if (cCharAt2 != '=') {
                                i4++;
                            } else {
                                int i5 = i4 + 1;
                                if (value.length() == i5) {
                                    pair2 = new Pair(Integer.valueOf(i5), "");
                                } else {
                                    char c = '\"';
                                    if (value.charAt(i5) == '\"') {
                                        int i6 = i4 + 2;
                                        StringBuilder sb = new StringBuilder();
                                        while (i6 <= StringsKt.J(value)) {
                                            char cCharAt3 = value.charAt(i6);
                                            if (cCharAt3 == c) {
                                                int i7 = i6 + 1;
                                                int i8 = i7;
                                                while (i8 < value.length() && value.charAt(i8) == ' ') {
                                                    i8++;
                                                }
                                                if (i8 == value.length() || value.charAt(i8) == ';') {
                                                    pair = new Pair(Integer.valueOf(i7), sb.toString());
                                                    break;
                                                }
                                            }
                                            if (cCharAt3 != '\\' || i6 >= StringsKt.J(value) - 2) {
                                                sb.append(cCharAt3);
                                                i6++;
                                            } else {
                                                sb.append(value.charAt(i6 + 1));
                                                i6 += 2;
                                            }
                                            c = '\"';
                                        }
                                        Integer numValueOf2 = Integer.valueOf(i6);
                                        String string = sb.toString();
                                        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                        pair = new Pair(numValueOf2, "\"" + string);
                                    } else {
                                        int i9 = i5;
                                        while (i9 <= StringsKt.J(value)) {
                                            char cCharAt4 = value.charAt(i9);
                                            if (cCharAt4 == ',' || cCharAt4 == ';') {
                                                pair = new Pair(Integer.valueOf(i9), Y6.d(i5, i9, value));
                                                break;
                                            }
                                            i9++;
                                        }
                                        pair = new Pair(Integer.valueOf(i9), Y6.d(i5, i9, value));
                                    }
                                    pair2 = pair;
                                }
                                int iIntValue = ((Number) pair2.a).intValue();
                                Y6.c(kVarA2, value, i3, i4, (String) pair2.b);
                                i = iIntValue;
                            }
                        }
                        Y6.c(kVarA2, value, i3, i4, "");
                        i = i4;
                    }
                } else {
                    ((ArrayList) kVarA.getValue()).add(new io.ktor.http.g(Y6.d(i2, numValueOf != null ? numValueOf.intValue() : i, value), kVarA2.isInitialized() ? (List) kVarA2.getValue() : kotlin.collections.K.a));
                }
            }
        }
        io.ktor.http.g gVar = (io.ktor.http.g) CollectionsKt.U(kVarA.isInitialized() ? (List) kVarA.getValue() : kotlin.collections.K.a);
        String str = gVar.a;
        int iL = StringsKt.L(str, '/', 0, false, 6);
        if (iL == -1) {
            if (Intrinsics.b(StringsKt.g0(str).toString(), "*")) {
                return io.ktor.http.d.f;
            }
            throw new BadContentTypeFormatException(value);
        }
        String strSubstring = str.substring(0, iL);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        String string2 = StringsKt.g0(strSubstring).toString();
        if (string2.length() == 0) {
            throw new BadContentTypeFormatException(value);
        }
        String strSubstring2 = str.substring(iL + 1);
        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
        String string3 = StringsKt.g0(strSubstring2).toString();
        if (StringsKt.F(string2, ' ', false) || StringsKt.F(string3, ' ', false)) {
            throw new BadContentTypeFormatException(value);
        }
        if (string3.length() == 0 || StringsKt.F(string3, '/', false)) {
            throw new BadContentTypeFormatException(value);
        }
        return new io.ktor.http.d(string2, string3, gVar.b);
    }
}
