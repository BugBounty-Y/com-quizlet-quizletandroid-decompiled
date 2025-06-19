package com.google.mlkit.vision.common.internal;

import android.os.SystemClock;
import android.util.Log;
import com.google.android.gms.common.internal.u;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class a {
    public static final com.quizlet.data.repository.widget.b c = new com.quizlet.data.repository.widget.b("StreamingFormatChecker", "");
    public final LinkedList a = new LinkedList();
    public long b = -1;

    public final void a(com.google.mlkit.vision.common.a aVar) {
        if (aVar.f != -1) {
            return;
        }
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        LinkedList linkedList = this.a;
        linkedList.add(Long.valueOf(jElapsedRealtime));
        if (linkedList.size() > 5) {
            linkedList.removeFirst();
        }
        if (linkedList.size() == 5) {
            Long l = (Long) linkedList.peekFirst();
            u.h(l);
            if (jElapsedRealtime - l.longValue() < 5000) {
                long j = this.b;
                if (j == -1 || jElapsedRealtime - j >= TimeUnit.SECONDS.toMillis(5L)) {
                    this.b = jElapsedRealtime;
                    com.quizlet.data.repository.widget.b bVar = c;
                    if (Log.isLoggable((String) bVar.b, 5)) {
                        Log.w("StreamingFormatChecker", bVar.t("ML Kit has detected that you seem to pass camera frames to the detector as a Bitmap object. This is inefficient. Please use YUV_420_888 format for camera2 API or NV21 format for (legacy) camera API and directly pass down the byte array to ML Kit."));
                    }
                }
            }
        }
    }
}
