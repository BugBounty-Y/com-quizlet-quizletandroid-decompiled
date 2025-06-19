package com.quizlet.quizletandroid.ui.common.images.capture;

import android.content.Context;
import androidx.work.impl.t;
import com.facebook.appevents.g;
import java.io.File;
import java.io.IOException;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.qutils.image.capture.a {
    @Override // com.quizlet.qutils.image.capture.a
    public final File a(Context context) {
        return b(context, "png");
    }

    @Override // com.quizlet.qutils.image.capture.a
    public final File b(Context context, String str) {
        if (str == null) {
            str = "png";
        }
        try {
            return t.b(g.e(context, "termimages"), str);
        } catch (IOException e) {
            timber.log.c.a(e);
            return null;
        }
    }

    @Override // com.quizlet.qutils.image.capture.a
    public final void d(Context context) {
        g.b(context, "termimages");
    }
}
