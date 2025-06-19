package androidx.datastore;

import android.content.Context;
import androidx.datastore.core.C1072d;
import androidx.datastore.core.InterfaceC1076h;
import androidx.datastore.core.P;
import androidx.datastore.core.okio.e;
import androidx.datastore.preferences.core.d;
import com.airbnb.lottie.network.c;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.n;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b {
    public final /* synthetic */ int a = 1;
    public final String b;
    public final c c;
    public final Object d;
    public final Object e;
    public final C f;
    public volatile InterfaceC1076h g;

    public b(String name, c cVar, Function1 produceMigrations, C scope) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(produceMigrations, "produceMigrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.b = name;
        this.c = cVar;
        this.e = produceMigrations;
        this.f = scope;
        this.d = new Object();
    }

    public final Object a(Object obj, n property) {
        P p;
        d dVar;
        switch (this.a) {
            case 0:
                Context thisRef = (Context) obj;
                Intrinsics.checkNotNullParameter(thisRef, "thisRef");
                Intrinsics.checkNotNullParameter(property, "property");
                P p2 = (P) this.g;
                if (p2 != null) {
                    return p2;
                }
                synchronized (this.d) {
                    try {
                        if (((P) this.g) == null) {
                            Context it2 = thisRef.getApplicationContext();
                            e storage = new e(okio.n.a, (com.quizlet.data.repository.school.membership.a) this.e, new androidx.credentials.playservices.controllers.BeginSignIn.d(9, it2, this));
                            c cVar = this.c;
                            Intrinsics.checkNotNullExpressionValue(it2, "applicationContext");
                            Intrinsics.checkNotNullParameter(it2, "it");
                            K migrations = K.a;
                            kotlinx.coroutines.internal.d scope = (kotlinx.coroutines.internal.d) this.f;
                            Intrinsics.checkNotNullParameter(storage, "storage");
                            Intrinsics.checkNotNullParameter(migrations, "migrations");
                            Intrinsics.checkNotNullParameter(scope, "scope");
                            Intrinsics.checkNotNullParameter(migrations, "migrations");
                            this.g = new P(storage, A.b(new C1072d(migrations, null)), cVar, scope);
                        }
                        p = (P) this.g;
                        Intrinsics.d(p);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return p;
            default:
                Context thisRef2 = (Context) obj;
                Intrinsics.checkNotNullParameter(thisRef2, "thisRef");
                Intrinsics.checkNotNullParameter(property, "property");
                d dVar2 = (d) this.g;
                if (dVar2 != null) {
                    return dVar2;
                }
                synchronized (this.d) {
                    try {
                        if (((d) this.g) == null) {
                            Context applicationContext = thisRef2.getApplicationContext();
                            c cVar2 = this.c;
                            Function1 function1 = (Function1) this.e;
                            Intrinsics.checkNotNullExpressionValue(applicationContext, "applicationContext");
                            this.g = androidx.datastore.preferences.core.e.d(cVar2, (List) function1.invoke(applicationContext), this.f, new androidx.credentials.playservices.controllers.BeginSignIn.d(10, applicationContext, this));
                        }
                        dVar = (d) this.g;
                        Intrinsics.d(dVar);
                    } catch (Throwable th2) {
                        throw th2;
                    }
                }
                return dVar;
        }
    }

    public b(String fileName, com.quizlet.data.repository.school.membership.a serializer, c cVar, kotlinx.coroutines.internal.d scope) {
        a produceMigrations = a.a;
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(produceMigrations, "produceMigrations");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.b = fileName;
        this.e = serializer;
        this.c = cVar;
        this.f = scope;
        this.d = new Object();
    }
}
