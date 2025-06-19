package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.quizlet.qutils.android.f;
import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.serializable_model.SerializableGBFeature;
import com.sdk.growthbook.serializable_model.SerializableGBFeatureKt;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import kotlin.text.D;
import kotlin.text.StringsKt__StringsKt;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.c;
import kotlinx.serialization.json.g;
import kotlinx.serialization.json.q;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CryptoKt {
    @NotNull
    public static final byte[] decodeBase64(@NotNull String base64) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        Intrinsics.checkNotNullParameter(base64, "base64");
        int[] iArr = com.soywiz.krypto.encoding.a.a;
        int length = base64.length();
        byte[] bArr = new byte[length];
        int i6 = 0;
        for (int i7 = 0; i7 < length; i7++) {
            bArr[i7] = (byte) base64.charAt(i7);
        }
        byte[] bArr2 = new byte[length];
        int[] iArr2 = com.soywiz.krypto.encoding.a.a;
        int i8 = 0;
        while (i6 < length) {
            int i9 = iArr2[bArr[i6] & 255];
            if (i9 < 0) {
                i6++;
            } else {
                if (i6 < length) {
                    i6++;
                } else {
                    i9 = 64;
                }
                if (i6 < length) {
                    i = i6 + 1;
                    i2 = iArr2[bArr[i6] & 255];
                } else {
                    i = i6;
                    i2 = 64;
                }
                if (i < length) {
                    i3 = i + 1;
                    i4 = iArr2[bArr[i] & 255];
                } else {
                    i3 = i;
                    i4 = 64;
                }
                if (i3 < length) {
                    i5 = iArr2[bArr[i3] & 255];
                    i3++;
                } else {
                    i5 = 64;
                }
                int i10 = i8 + 1;
                bArr2[i8] = (byte) ((i9 << 2) | (i2 >> 4));
                if (i4 < 64) {
                    int i11 = i8 + 2;
                    bArr2[i10] = (byte) ((i2 << 4) | (i4 >> 2));
                    if (i5 < 64) {
                        i8 += 3;
                        bArr2[i11] = (byte) ((i4 << 6) | i5);
                    } else {
                        i8 = i11;
                    }
                    i6 = i3;
                } else {
                    i6 = i3;
                    i8 = i10;
                }
            }
        }
        byte[] bArrCopyOf = Arrays.copyOf(bArr2, i8);
        Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(this, newSize)");
        return bArrCopyOf;
    }

    public static final Map<String, GBFeature> encryptToFeaturesDataModel(@NotNull String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        q qVarC = Y1.c(new f(29));
        try {
            R1.g(N.a);
            q0 q0Var = q0.a;
            Map map = (Map) qVarC.b(string, R1.b(SerializableGBFeature.Companion.serializer()));
            LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
            for (Object obj : map.entrySet()) {
                linkedHashMap.put(((Map.Entry) obj).getKey(), SerializableGBFeatureKt.gbDeserialize((SerializableGBFeature) ((Map.Entry) obj).getValue()));
            }
            return linkedHashMap;
        } catch (Exception unused) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit encryptToFeaturesDataModel$lambda$0(g Json) {
        Intrinsics.checkNotNullParameter(Json, "$this$Json");
        Json.e = true;
        Json.d = true;
        Json.c = true;
        return Unit.a;
    }

    public static final Map<String, GBFeature> getFeaturesFromEncryptedFeatures(@NotNull String encryptedString, @NotNull String encryptionKey, Crypto crypto) {
        Intrinsics.checkNotNullParameter(encryptedString, "encryptedString");
        Intrinsics.checkNotNullParameter(encryptionKey, "encryptionKey");
        List listSplit$default = StringsKt__StringsKt.split$default(encryptedString, new String[]{"."}, false, 0, 6, null);
        byte[] bArrDecodeBase64 = decodeBase64((String) listSplit$default.get(0));
        byte[] bArrDecodeBase642 = decodeBase64(encryptionKey);
        byte[] bArrDecodeBase643 = decodeBase64((String) listSplit$default.get(1));
        if (crypto == null) {
            crypto = new DefaultCrypto();
        }
        return encryptToFeaturesDataModel(D.i(crypto.decrypt(bArrDecodeBase643, bArrDecodeBase642, bArrDecodeBase64)));
    }

    public static /* synthetic */ Map getFeaturesFromEncryptedFeatures$default(String str, String str2, Crypto crypto, int i, Object obj) {
        if ((i & 4) != 0) {
            crypto = null;
        }
        return getFeaturesFromEncryptedFeatures(str, str2, crypto);
    }

    public static final v getSavedGroupFromEncryptedSavedGroup(@NotNull String encryptedString, @NotNull String encryptionKey, Crypto crypto) {
        Intrinsics.checkNotNullParameter(encryptedString, "encryptedString");
        Intrinsics.checkNotNullParameter(encryptionKey, "encryptionKey");
        List listSplit$default = StringsKt__StringsKt.split$default(encryptedString, new String[]{"."}, false, 0, 6, null);
        byte[] bArrDecodeBase64 = decodeBase64((String) listSplit$default.get(0));
        byte[] bArrDecodeBase642 = decodeBase64(encryptionKey);
        byte[] bArrDecodeBase643 = decodeBase64((String) listSplit$default.get(1));
        if (crypto == null) {
            crypto = new DefaultCrypto();
        }
        try {
            return (v) c.d.b(D.i(crypto.decrypt(bArrDecodeBase643, bArrDecodeBase642, bArrDecodeBase64)), v.Companion.serializer());
        } catch (Exception unused) {
            return null;
        }
    }

    public static /* synthetic */ v getSavedGroupFromEncryptedSavedGroup$default(String str, String str2, Crypto crypto, int i, Object obj) {
        if ((i & 4) != 0) {
            crypto = null;
        }
        return getSavedGroupFromEncryptedSavedGroup(str, str2, crypto);
    }
}
