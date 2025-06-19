package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public abstract class R3 {
    public static final void a(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        Function0 function04;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1077493860);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
            function04 = function02;
        } else {
            function03 = function0;
            function04 = function02;
            W5.a(R.string.uuf_go_back_dialog_confirm_button, R.string.uuf_go_back_dialog_message, null, function03, function04, null, Integer.valueOf(R.string.uuf_go_back_dialog_title), Integer.valueOf(R.string.uuf_go_back_dialog_cancel_button), c0814p, (i2 << 9) & 64512, 36);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function03, function04, i, 4);
        }
    }

    public static String b(InputStream inputStream, long j, int i) {
        byte[] bArr = new byte[1024];
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            inputStream.skip(j);
            if (i <= 0) {
                i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            }
            while (i > 0) {
                int i2 = inputStream.read(bArr, 0, Math.min(i, 1024));
                if (i2 == -1) {
                    break;
                }
                byteArrayOutputStream.write(bArr, 0, i2);
                i -= i2;
            }
            inputStream.close();
            try {
                return byteArrayOutputStream.toString("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("Unsupported encoding UTF8. This should always be supported.", e);
            }
        } catch (IOException e2) {
            throw new RuntimeException("Failed to read license or metadata text.", e2);
        }
    }
}
