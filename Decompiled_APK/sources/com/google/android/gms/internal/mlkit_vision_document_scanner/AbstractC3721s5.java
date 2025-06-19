package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.s5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3721s5 {
    /* JADX WARN: Removed duplicated region for block: B:101:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0137  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x014d  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0162  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x01ed  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x01fa  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0252  */
    /* JADX WARN: Removed duplicated region for block: B:141:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x00ff  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.assembly.compose.components.flashcards.b r31, androidx.compose.ui.q r32, com.quizlet.assembly.compose.components.flashcards.d r33, androidx.compose.foundation.interaction.l r34, long r35, androidx.compose.foundation.C0555x r37, androidx.compose.material3.Y r38, kotlin.jvm.functions.Function1 r39, androidx.compose.runtime.internal.d r40, androidx.compose.runtime.internal.d r41, int r42, androidx.compose.runtime.InterfaceC0806l r43, int r44, int r45) {
        /*
            Method dump skipped, instructions count: 610
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5.a(com.quizlet.assembly.compose.components.flashcards.b, androidx.compose.ui.q, com.quizlet.assembly.compose.components.flashcards.d, androidx.compose.foundation.interaction.l, long, androidx.compose.foundation.x, androidx.compose.material3.Y, kotlin.jvm.functions.Function1, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, int, androidx.compose.runtime.l, int, int):void");
    }

    public static Intent b(Context context) {
        Intent intentB = AbstractC4178x.b(context, "context", context, QuizletLiveActivity.class);
        intentB.putExtra("extra.url", "https://quizlet.com/oauthweb/live");
        intentB.putExtra("extra.mTitle", context.getString(R.string.quizlet_live_activity_title));
        return intentB;
    }

    public static Intent c(Context context, String gameCode) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(gameCode, "gameCode");
        String strS = androidx.compose.animation.d0.s(new Object[]{gameCode}, 1, "https://quizlet.com/oauthweb/live/%s", "format(...)");
        Intent intent = new Intent(context, (Class<?>) QuizletLiveActivity.class);
        intent.putExtra("extra.url", strS);
        intent.putExtra("extra.mTitle", context.getString(R.string.quizlet_live_activity_title));
        return intent;
    }
}
