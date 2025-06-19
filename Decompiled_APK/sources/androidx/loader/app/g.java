package androidx.loader.app;

import android.os.Looper;
import androidx.collection.W;
import androidx.compose.ui.node.B;
import androidx.lifecycle.B0;
import androidx.lifecycle.J;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.quizlet.data.repository.metering.j;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes.dex */
public final class g extends b {
    public final Object a;
    public final f b;

    public g(J j, B0 store) {
        this.a = j;
        e factory = f.d;
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        androidx.lifecycle.viewmodel.a defaultCreationExtras = androidx.lifecycle.viewmodel.a.b;
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        j jVar = new j(store, factory, defaultCreationExtras);
        Intrinsics.checkNotNullParameter(f.class, "modelClass");
        Intrinsics.checkNotNullParameter(f.class, "<this>");
        C4950i modelClass = K.a(f.class);
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        this.b = (f) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [androidx.lifecycle.J, java.lang.Object] */
    @Override // androidx.loader.app.b
    public final androidx.loader.content.c a(int i, a aVar) {
        f fVar = this.b;
        if (fVar.c) {
            throw new IllegalStateException("Called while creating a loader");
        }
        if (Looper.getMainLooper() != Looper.myLooper()) {
            throw new IllegalStateException("initLoader must be called on the main thread");
        }
        c cVar = (c) fVar.b.d(i);
        ?? r2 = this.a;
        if (cVar != 0) {
            androidx.loader.content.c cVar2 = cVar.m;
            d dVar = new d(cVar2, aVar);
            cVar.f(r2, dVar);
            d dVar2 = cVar.o;
            if (dVar2 != null) {
                cVar.k(dVar2);
            }
            cVar.n = r2;
            cVar.o = dVar;
            return cVar2;
        }
        try {
            fVar.c = true;
            androidx.loader.content.c cVarP = aVar.p();
            if (cVarP == null) {
                throw new IllegalArgumentException("Object returned from onCreateLoader must not be null");
            }
            if (cVarP.getClass().isMemberClass() && !Modifier.isStatic(cVarP.getClass().getModifiers())) {
                throw new IllegalArgumentException("Object returned from onCreateLoader must not be a non-static inner member class: " + cVarP);
            }
            c cVar3 = new c(i, cVarP);
            fVar.b.f(i, cVar3);
            fVar.c = false;
            androidx.loader.content.c cVar4 = cVar3.m;
            d dVar3 = new d(cVar4, aVar);
            cVar3.f(r2, dVar3);
            d dVar4 = cVar3.o;
            if (dVar4 != null) {
                cVar3.k(dVar4);
            }
            cVar3.n = r2;
            cVar3.o = dVar3;
            return cVar4;
        } catch (Throwable th) {
            fVar.c = false;
            throw th;
        }
    }

    public final void b(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        W w = this.b.b;
        if (w.g() > 0) {
            printWriter.print(str);
            printWriter.println("Loaders:");
            String str2 = str + "    ";
            for (int i = 0; i < w.g(); i++) {
                c cVar = (c) w.h(i);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(w.e(i));
                printWriter.print(": ");
                printWriter.println(cVar.toString());
                printWriter.print(str2);
                printWriter.print("mId=");
                printWriter.print(cVar.l);
                printWriter.print(" mArgs=");
                printWriter.println((Object) null);
                printWriter.print(str2);
                printWriter.print("mLoader=");
                androidx.loader.content.c cVar2 = cVar.m;
                printWriter.println(cVar2);
                cVar2.b(str2 + "  ", fileDescriptor, printWriter, strArr);
                if (cVar.o != null) {
                    printWriter.print(str2);
                    printWriter.print("mCallbacks=");
                    printWriter.println(cVar.o);
                    d dVar = cVar.o;
                    dVar.getClass();
                    printWriter.print(str2 + "  ");
                    printWriter.print("mDeliveredData=");
                    printWriter.println(dVar.b);
                }
                printWriter.print(str2);
                printWriter.print("mData=");
                Object objD = cVar.d();
                StringBuilder sb = new StringBuilder(64);
                if (objD == null) {
                    sb.append("null");
                } else {
                    Class<?> cls = objD.getClass();
                    sb.append(cls.getSimpleName());
                    sb.append("{");
                    sb.append(Integer.toHexString(System.identityHashCode(cls)));
                    sb.append("}");
                }
                printWriter.println(sb.toString());
                printWriter.print(str2);
                printWriter.print("mStarted=");
                printWriter.println(cVar.e());
            }
        }
    }

    public final String toString() {
        StringBuilder sbL = B.l(128, "LoaderManager{");
        sbL.append(Integer.toHexString(System.identityHashCode(this)));
        sbL.append(" in ");
        Class<?> cls = this.a.getClass();
        sbL.append(cls.getSimpleName());
        sbL.append("{");
        sbL.append(Integer.toHexString(System.identityHashCode(cls)));
        sbL.append("}}");
        return sbL.toString();
    }
}
