package com.google.android.gms.cloudmessaging;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import java.io.IOException;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements com.google.android.gms.tasks.a, com.google.android.gms.tasks.e {
    public static final /* synthetic */ c b = new c(0);
    public static final /* synthetic */ c c = new c(1);
    public static final /* synthetic */ c d = new c(2);
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        Bundle bundle = (Bundle) obj;
        int i = a.h;
        return (bundle == null || !bundle.containsKey("google.messenger")) ? S3.i(bundle) : S3.i(null);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) throws IOException {
        switch (this.a) {
            case 0:
                if (task.l()) {
                    return (Bundle) task.h();
                }
                if (Log.isLoggable("Rpc", 3)) {
                    "Error making request: ".concat(String.valueOf(task.g()));
                }
                throw new IOException("SERVICE_NOT_AVAILABLE", task.g());
            default:
                Intent intent = (Intent) ((Bundle) task.h()).getParcelable("notification_data");
                if (intent != null) {
                    return new CloudMessage(intent);
                }
                return null;
        }
    }
}
