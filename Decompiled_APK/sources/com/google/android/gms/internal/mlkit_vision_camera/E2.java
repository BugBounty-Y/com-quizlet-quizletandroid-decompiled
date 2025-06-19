package com.google.android.gms.internal.mlkit_vision_camera;

import android.net.NetworkRequest;
import android.text.Spannable;
import android.util.Log;
import com.quizlet.data.model.AbstractC4178x;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class E2 {
    public static final /* synthetic */ int a = 0;

    public static androidx.work.impl.utils.g a(int[] capabilities, int[] transports) {
        Intrinsics.checkNotNullParameter(capabilities, "capabilities");
        Intrinsics.checkNotNullParameter(transports, "transports");
        Intrinsics.checkNotNullParameter(capabilities, "capabilities");
        Intrinsics.checkNotNullParameter(transports, "transports");
        NetworkRequest.Builder builder = new NetworkRequest.Builder();
        for (int i : capabilities) {
            try {
                builder.addCapability(i);
            } catch (IllegalArgumentException e) {
                androidx.work.z zVarC = androidx.work.z.c();
                String str = androidx.work.impl.utils.g.b;
                String str2 = androidx.work.impl.utils.g.b;
                String strM = androidx.compose.animation.d0.m('\'', i, "Ignoring adding capability '");
                if (zVarC.a <= 5) {
                    Log.w(str2, strM, e);
                }
            }
        }
        for (int i2 : transports) {
            builder.addTransportType(i2);
        }
        NetworkRequest networkRequestBuild = builder.build();
        Intrinsics.checkNotNullExpressionValue(networkRequestBuild, "networkRequest.build()");
        return new androidx.work.impl.utils.g(networkRequestBuild);
    }

    public static void b(Spannable text, org.wordpress.aztec.spans.D block, int i, int i2) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(block, "block");
        if (i <= i2) {
            if (org.wordpress.aztec.util.b.e(text, i, i2, 51)) {
                return;
            }
            text.setSpan(block, i, i2, 51);
            return;
        }
        org.wordpress.android.util.a.c("BlockHandler.set static method called with start > end. Start: " + i + " End: " + i2);
        StringBuilder sb = new StringBuilder("Invoked with block type of ");
        sb.append(block.getClass().getCanonicalName());
        org.wordpress.android.util.a.c(sb.toString());
        com.quizlet.quizletandroid.ui.profile.p pVar = org.wordpress.aztec.util.b.a;
        Intrinsics.checkNotNullParameter(text, "text");
        try {
            pVar.f(text);
            AbstractC4178x.u(2);
            org.wordpress.android.util.a.a();
        } catch (Exception e) {
            ArrayList arrayList = org.wordpress.android.util.a.a;
            Log.e("WordPress-EDITOR", "Uhh ohh! There was an error logging the spans details of the Editor. This shouldnever happen.", e);
            e.getMessage();
            org.wordpress.android.util.a.a();
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            stringWriter.toString();
            org.wordpress.android.util.a.a();
        }
    }
}
