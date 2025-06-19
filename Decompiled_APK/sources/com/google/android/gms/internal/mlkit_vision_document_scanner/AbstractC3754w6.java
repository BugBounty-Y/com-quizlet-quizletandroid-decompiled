package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.studiablemodels.StudiableAudio;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.w6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3754w6 {
    public static final void a(com.quizlet.learn.checkpoint.data.d selectableTermShapedCard, boolean z, kotlin.jvm.functions.d onAudioIconClick, kotlin.jvm.functions.c onSectionTextClick, Function2 onStarToggle, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(selectableTermShapedCard, "selectableTermShapedCard");
        Intrinsics.checkNotNullParameter(onAudioIconClick, "onAudioIconClick");
        Intrinsics.checkNotNullParameter(onSectionTextClick, "onSectionTextClick");
        Intrinsics.checkNotNullParameter(onStarToggle, "onStarToggle");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1988649118);
        int i2 = i | (c0814p2.h(selectableTermShapedCard) ? 4 : 2) | (c0814p2.g(z) ? 32 : 16) | (c0814p2.h(onAudioIconClick) ? 256 : 128) | (c0814p2.h(onSectionTextClick) ? 2048 : 1024) | (c0814p2.h(onStarToggle) ? 16384 : 8192) | (c0814p2.f(qVar) ? 131072 : 65536);
        if ((74899 & i2) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            com.quizlet.studiablemodels.i iVar = selectableTermShapedCard.a;
            c0814p = c0814p2;
            long j = iVar.a;
            com.quizlet.features.infra.models.a aVarF = com.google.android.gms.internal.mlkit_vision_barcode.B6.f(iVar.b.c, false);
            com.quizlet.studiablemodels.i iVar2 = selectableTermShapedCard.a;
            com.quizlet.features.infra.models.a aVarF2 = com.google.android.gms.internal.mlkit_vision_barcode.B6.f(iVar2.c.c, false);
            Boolean boolValueOf = z ? Boolean.valueOf(selectableTermShapedCard.b) : null;
            StudiableAudio studiableAudio = iVar2.b.e;
            String str = studiableAudio != null ? studiableAudio.a : null;
            StudiableAudio studiableAudio2 = iVar2.c.e;
            String str2 = studiableAudio2 != null ? studiableAudio2.a : null;
            Boolean bool = boolValueOf;
            String str3 = str2;
            String str4 = str;
            com.google.android.gms.internal.mlkit_vision_common.I3.c(j, aVarF, aVarF2, bool, iVar2.e, str4, str3, iVar2.d, androidx.compose.ui.platform.N.G(qVar, "term_item_tag"), onStarToggle, onAudioIconClick, onSectionTextClick, 0, c0814p, (i2 << 15) & 1879048192, (i2 >> 6) & 126, 4096);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.emailconfirmation.ui.composables.e(selectableTermShapedCard, z, onAudioIconClick, onSectionTextClick, onStarToggle, qVar, i);
        }
    }

    public static final String b(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        String str2 = Instant.parse(str).atOffset(ZoneOffset.UTC).toLocalDate().format(DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT));
        Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
        return str2;
    }
}
