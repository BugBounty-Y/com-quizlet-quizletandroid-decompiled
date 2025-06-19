package com.google.firebase.remoteconfig;

import android.util.Log;
import androidx.camera.camera2.internal.T;
import androidx.work.impl.model.l;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.firebase.abt.AbtException;
import com.google.firebase.remoteconfig.internal.k;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements com.google.android.gms.tasks.e, com.google.android.gms.tasks.a {
    public final /* synthetic */ b a;

    public /* synthetic */ a(b bVar) {
        this.a = bVar;
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        b bVar = this.a;
        Task taskB = bVar.c.b();
        Task taskB2 = bVar.d.b();
        return S3.k(taskB, taskB2).f(bVar.b, new T(bVar, taskB, taskB2, 14));
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) throws Throwable {
        boolean z;
        b bVar = this.a;
        bVar.getClass();
        if (task.l()) {
            com.google.firebase.remoteconfig.internal.b bVar2 = bVar.c;
            synchronized (bVar2) {
                bVar2.c = S3.i(null);
            }
            k kVar = bVar2.b;
            synchronized (kVar) {
                kVar.a.deleteFile(kVar.b);
            }
            com.google.firebase.remoteconfig.internal.c cVar = (com.google.firebase.remoteconfig.internal.c) task.h();
            if (cVar != null) {
                JSONArray jSONArray = cVar.d;
                com.google.firebase.abt.b bVar3 = bVar.a;
                if (bVar3 != null) {
                    try {
                        bVar3.c(b.d(jSONArray));
                    } catch (AbtException e) {
                        Log.w("FirebaseRemoteConfig", "Could not update ABT experiments.", e);
                    } catch (JSONException e2) {
                        Log.e("FirebaseRemoteConfig", "Could not parse ABT experiments from the JSON response.", e2);
                    }
                }
                com.quizlet.data.repository.explanations.question.a aVar = bVar.i;
                try {
                    com.google.firebase.remoteconfig.interop.rollouts.d dVarJ = ((l) aVar.b).j(cVar);
                    Iterator it2 = ((Set) aVar.d).iterator();
                    while (it2.hasNext()) {
                        ((Executor) aVar.c).execute(new com.google.firebase.remoteconfig.internal.rollouts.a((com.google.firebase.crashlytics.internal.b) it2.next(), dVarJ, 0));
                    }
                } catch (FirebaseRemoteConfigException e3) {
                    Log.w("FirebaseRemoteConfig", "Exception publishing RolloutsState to subscribers. Continuing to listen for changes.", e3);
                }
            } else {
                Log.e("FirebaseRemoteConfig", "Activated configs written to disk are null.");
            }
            z = true;
        } else {
            z = false;
        }
        return Boolean.valueOf(z);
    }
}
