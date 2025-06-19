package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.MatchResult;
import kotlin.text.Regex;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.z6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3778z6 {
    public static final /* synthetic */ int a = 0;

    public static final int a(com.quizlet.data.model.billing.a aVar) throws NumberFormatException {
        int i;
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        String str = aVar.f;
        int i2 = 0;
        if (str != null && str.length() != 0) {
            String str2 = aVar.f;
            androidx.collection.L l = new androidx.collection.L(c(aVar, str2));
            while (l.hasNext()) {
                kotlin.text.m mVar = (kotlin.text.m) ((MatchResult) l.next()).a().b;
                String str3 = (String) ((kotlin.collections.W) mVar.b()).get(1);
                String str4 = (String) ((kotlin.collections.W) mVar.b()).get(2);
                if (Intrinsics.b(str4, "W")) {
                    i = Integer.parseInt(str3) * 7;
                } else {
                    if (!Intrinsics.b(str4, "D")) {
                        throw new NumberFormatException(android.support.v4.media.session.a.t(AbstractC0147y.h("Unknown modifier '", str4, "' (from '", str2, "') for SKU: ("), aVar.a, ")"));
                    }
                    i = Integer.parseInt(str3);
                }
                i2 += i;
            }
        }
        return i2;
    }

    public static final com.quizlet.data.model.billing.b b(com.quizlet.data.model.billing.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        kotlin.sequences.g gVarC = c(aVar, aVar.e);
        int iD = kotlin.sequences.q.d(gVarC);
        String str = aVar.a;
        String str2 = aVar.e;
        if (iD > 1) {
            throw new NumberFormatException(AbstractC0147y.e("Not a valid subscription period: (", str2, ") for SKU: (", str, ")"));
        }
        Intrinsics.checkNotNullParameter(gVarC, "<this>");
        androidx.collection.L l = new androidx.collection.L(gVarC);
        if (!l.hasNext()) {
            throw new NoSuchElementException("Sequence is empty.");
        }
        String str3 = (String) ((kotlin.collections.W) ((kotlin.text.m) ((MatchResult) l.next()).a().b).b()).get(2);
        if (Intrinsics.b(str3, "M")) {
            return com.quizlet.data.model.billing.b.a;
        }
        if (Intrinsics.b(str3, "Y")) {
            return com.quizlet.data.model.billing.b.b;
        }
        throw new NumberFormatException(android.support.v4.media.session.a.t(AbstractC0147y.h("Not a valid modifier `", str3, "` (from `", str2, "`) for SKU: ("), str, ")"));
    }

    public static final kotlin.sequences.g c(com.quizlet.data.model.billing.a aVar, String str) {
        kotlin.sequences.g gVarC = Regex.c(new Regex("(\\d+)([A-Z])"), str);
        if (kotlin.sequences.q.d(gVarC) > 0) {
            return gVarC;
        }
        throw new NumberFormatException(AbstractC0147y.e("Not a valid period: (", str, ") for SKU: (", aVar.a, ")"));
    }
}
