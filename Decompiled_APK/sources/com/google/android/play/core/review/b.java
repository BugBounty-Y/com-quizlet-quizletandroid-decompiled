package com.google.android.play.core.review;

import android.app.Activity;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.f;
import com.google.android.play.core.common.PlayCoreDialogWrapperActivity;

/* loaded from: classes2.dex */
public final class b {
    public final d a;
    public final Handler b = new Handler(Looper.getMainLooper());

    public b(d dVar) {
        this.a = dVar;
    }

    public final void a(Activity activity, ReviewInfo reviewInfo) {
        zza zzaVar = (zza) reviewInfo;
        if (zzaVar.b) {
            S3.i(null);
            return;
        }
        Intent intent = new Intent(activity, (Class<?>) PlayCoreDialogWrapperActivity.class);
        intent.putExtra("confirmation_intent", zzaVar.a);
        intent.putExtra("window_flags", activity.getWindow().getDecorView().getWindowSystemUiVisibility());
        intent.putExtra("result_receiver", new zzc(this.b, new f()));
        activity.startActivity(intent);
    }
}
