package dagger.hilt.android.internal.managers;

import android.app.Activity;
import android.app.Application;
import androidx.activity.s;
import androidx.lifecycle.B0;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.C4624g;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class b implements dagger.hilt.internal.b {
    public final /* synthetic */ int a = 0;
    public final Object b = new Object();
    public final Activity c;
    public final Object d;
    public volatile dagger.hilt.internal.a e;

    public b(Activity activity) {
        this.c = activity;
        this.d = new b((s) activity);
    }

    public C4622e a() {
        String str;
        Activity activity = this.c;
        if (activity.getApplication() instanceof dagger.hilt.internal.b) {
            C4624g c4624g = (C4624g) ((a) K6.b(a.class, (b) this.d));
            return new C4622e(c4624g.b, c4624g.c, activity);
        }
        StringBuilder sb = new StringBuilder("Hilt Activity must be attached to an @HiltAndroidApp Application. ");
        if (Application.class.equals(activity.getApplication().getClass())) {
            str = "Did you forget to specify your Application's class name in your manifest's <application />'s android:name attribute?";
        } else {
            str = "Found: " + activity.getApplication().getClass();
        }
        sb.append(str);
        throw new IllegalStateException(sb.toString());
    }

    public com.quizlet.login.authentication.login.a b() {
        b bVar = (b) this.d;
        s owner = (s) bVar.c;
        androidx.lifecycle.viewmodel.d factory = new androidx.lifecycle.viewmodel.d((s) bVar.d, 2);
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(factory, "factory");
        B0 store = owner.getViewModelStore();
        Intrinsics.checkNotNullParameter(owner, "owner");
        androidx.lifecycle.viewmodel.c defaultCreationExtras = owner.getDefaultViewModelCreationExtras();
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
        Intrinsics.checkNotNullParameter(d.class, "modelClass");
        Intrinsics.checkNotNullParameter(d.class, "<this>");
        C4950i modelClass = K.a(d.class);
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB != null) {
            return ((d) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB))).c;
        }
        throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.a) {
            case 0:
                if (((C4622e) this.e) == null) {
                    synchronized (this.b) {
                        try {
                            if (((C4622e) this.e) == null) {
                                this.e = a();
                            }
                        } finally {
                        }
                    }
                }
                return (C4622e) this.e;
            default:
                if (((C4624g) this.e) == null) {
                    synchronized (this.b) {
                        if (((C4624g) this.e) == null) {
                            s owner = (s) this.c;
                            androidx.lifecycle.viewmodel.d factory = new androidx.lifecycle.viewmodel.d((s) this.d, 2);
                            Intrinsics.checkNotNullParameter(owner, "owner");
                            Intrinsics.checkNotNullParameter(factory, "factory");
                            B0 store = owner.getViewModelStore();
                            Intrinsics.checkNotNullParameter(owner, "owner");
                            androidx.lifecycle.viewmodel.c defaultCreationExtras = owner.getDefaultViewModelCreationExtras();
                            Intrinsics.checkNotNullParameter(store, "store");
                            Intrinsics.checkNotNullParameter(factory, "factory");
                            Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
                            com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
                            Intrinsics.checkNotNullParameter(d.class, "modelClass");
                            Intrinsics.checkNotNullParameter(d.class, "<this>");
                            C4950i modelClass = K.a(d.class);
                            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                            String strB = C1.b(modelClass);
                            if (strB == null) {
                                throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
                            }
                            this.e = ((d) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB))).b;
                        }
                    }
                }
                return (C4624g) this.e;
        }
    }

    public b(s sVar) {
        this.c = sVar;
        this.d = sVar;
    }
}
