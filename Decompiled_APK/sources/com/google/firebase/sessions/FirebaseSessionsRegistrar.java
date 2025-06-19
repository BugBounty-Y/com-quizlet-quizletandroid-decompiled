package com.google.firebase.sessions;

import android.content.Context;
import android.util.Log;
import androidx.annotation.Keep;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import java.util.List;
import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class FirebaseSessionsRegistrar implements ComponentRegistrar {

    @NotNull
    private static final C4001x Companion = new C4001x();

    @Deprecated
    @NotNull
    public static final String LIBRARY_NAME = "fire-sessions";

    @Deprecated
    @NotNull
    public static final String TAG = "FirebaseSessions";

    @NotNull
    private static final com.google.firebase.components.q appContext;

    @NotNull
    private static final com.google.firebase.components.q backgroundDispatcher;

    @NotNull
    private static final com.google.firebase.components.q blockingDispatcher;

    @NotNull
    private static final com.google.firebase.components.q firebaseApp;

    @NotNull
    private static final com.google.firebase.components.q firebaseInstallationsApi;

    @NotNull
    private static final com.google.firebase.components.q firebaseSessionsComponent;

    @NotNull
    private static final com.google.firebase.components.q transportFactory;

    static {
        com.google.firebase.components.q qVarA = com.google.firebase.components.q.a(Context.class);
        Intrinsics.checkNotNullExpressionValue(qVarA, "unqualified(Context::class.java)");
        appContext = qVarA;
        com.google.firebase.components.q qVarA2 = com.google.firebase.components.q.a(com.google.firebase.h.class);
        Intrinsics.checkNotNullExpressionValue(qVarA2, "unqualified(FirebaseApp::class.java)");
        firebaseApp = qVarA2;
        com.google.firebase.components.q qVarA3 = com.google.firebase.components.q.a(com.google.firebase.installations.d.class);
        Intrinsics.checkNotNullExpressionValue(qVarA3, "unqualified(FirebaseInstallationsApi::class.java)");
        firebaseInstallationsApi = qVarA3;
        com.google.firebase.components.q qVar = new com.google.firebase.components.q(com.google.firebase.annotations.concurrent.a.class, AbstractC5040y.class);
        Intrinsics.checkNotNullExpressionValue(qVar, "qualified(Background::cl…neDispatcher::class.java)");
        backgroundDispatcher = qVar;
        com.google.firebase.components.q qVar2 = new com.google.firebase.components.q(com.google.firebase.annotations.concurrent.b.class, AbstractC5040y.class);
        Intrinsics.checkNotNullExpressionValue(qVar2, "qualified(Blocking::clas…neDispatcher::class.java)");
        blockingDispatcher = qVar2;
        com.google.firebase.components.q qVarA4 = com.google.firebase.components.q.a(com.google.android.datatransport.f.class);
        Intrinsics.checkNotNullExpressionValue(qVarA4, "unqualified(TransportFactory::class.java)");
        transportFactory = qVarA4;
        com.google.firebase.components.q qVarA5 = com.google.firebase.components.q.a(InterfaceC3996s.class);
        Intrinsics.checkNotNullExpressionValue(qVarA5, "unqualified(FirebaseSessionsComponent::class.java)");
        firebaseSessionsComponent = qVarA5;
        try {
            int i = AbstractC4000w.a;
        } catch (NoClassDefFoundError unused) {
            Log.w(TAG, "Your app is experiencing a known issue in the Android Gradle plugin, see https://issuetracker.google.com/328687152\n\nIt affects Java-only apps using AGP version 8.3.2 and under. To avoid the issue, either:\n\n1. Upgrade Android Gradle plugin to 8.4.0+\n   Follow the guide at https://developer.android.com/build/agp-upgrade-assistant\n\n2. Or, add the Kotlin plugin to your app\n   Follow the guide at https://developer.android.com/kotlin/add-kotlin\n\n3. Or, do the technical workaround described in https://issuetracker.google.com/issues/328687152#comment3");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C3994p getComponents$lambda$0(com.google.firebase.components.b bVar) {
        return (C3994p) ((C3987i) ((InterfaceC3996s) bVar.f(firebaseSessionsComponent))).i.get();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final InterfaceC3996s getComponents$lambda$1(com.google.firebase.components.b bVar) {
        Object objF = bVar.f(appContext);
        Intrinsics.checkNotNullExpressionValue(objF, "container[appContext]");
        Context context = (Context) objF;
        context.getClass();
        Object objF2 = bVar.f(backgroundDispatcher);
        Intrinsics.checkNotNullExpressionValue(objF2, "container[backgroundDispatcher]");
        CoroutineContext coroutineContext = (CoroutineContext) objF2;
        coroutineContext.getClass();
        Object objF3 = bVar.f(blockingDispatcher);
        Intrinsics.checkNotNullExpressionValue(objF3, "container[blockingDispatcher]");
        ((CoroutineContext) objF3).getClass();
        Object objF4 = bVar.f(firebaseApp);
        Intrinsics.checkNotNullExpressionValue(objF4, "container[firebaseApp]");
        com.google.firebase.h hVar = (com.google.firebase.h) objF4;
        hVar.getClass();
        Object objF5 = bVar.f(firebaseInstallationsApi);
        Intrinsics.checkNotNullExpressionValue(objF5, "container[firebaseInstallationsApi]");
        com.google.firebase.installations.d dVar = (com.google.firebase.installations.d) objF5;
        dVar.getClass();
        com.google.firebase.inject.b bVarA = bVar.a(transportFactory);
        Intrinsics.checkNotNullExpressionValue(bVarA, "container.getProvider(transportFactory)");
        bVarA.getClass();
        C3987i c3987i = new C3987i();
        c3987i.a = com.google.firebase.sessions.dagger.internal.c.a(hVar);
        com.google.firebase.sessions.dagger.internal.c cVarA = com.google.firebase.sessions.dagger.internal.c.a(context);
        c3987i.b = cVarA;
        c3987i.c = com.google.firebase.sessions.dagger.internal.a.a(new C3991m(cVarA, 5));
        c3987i.d = com.google.firebase.sessions.dagger.internal.c.a(coroutineContext);
        c3987i.e = com.google.firebase.sessions.dagger.internal.c.a(dVar);
        javax.inject.a aVarA = com.google.firebase.sessions.dagger.internal.a.a(new C3991m(c3987i.a, 1));
        c3987i.f = aVarA;
        c3987i.g = com.google.firebase.sessions.dagger.internal.a.a(new M(aVarA, c3987i.d));
        c3987i.h = com.google.firebase.sessions.dagger.internal.a.a(new X(c3987i.c, com.google.firebase.sessions.dagger.internal.a.a(new V(c3987i.d, c3987i.e, c3987i.f, c3987i.g, com.google.firebase.sessions.dagger.internal.a.a(new C3991m(com.google.firebase.sessions.dagger.internal.a.a(new C3991m(c3987i.b, 2)), 6)), 1)), 1));
        c3987i.i = com.google.firebase.sessions.dagger.internal.a.a(new C4002y(c3987i.a, c3987i.h, c3987i.d, com.google.firebase.sessions.dagger.internal.a.a(new C3991m(c3987i.b, 4))));
        c3987i.j = com.google.firebase.sessions.dagger.internal.a.a(new M(c3987i.d, com.google.firebase.sessions.dagger.internal.a.a(new C3991m(c3987i.b, 3))));
        c3987i.k = com.google.firebase.sessions.dagger.internal.a.a(new V(c3987i.a, c3987i.e, c3987i.h, com.google.firebase.sessions.dagger.internal.a.a(new C3991m(com.google.firebase.sessions.dagger.internal.c.a(bVarA), 0)), c3987i.d, 0));
        c3987i.l = com.google.firebase.sessions.dagger.internal.a.a(AbstractC3997t.a);
        c3987i.m = com.google.firebase.sessions.dagger.internal.a.a(new X(c3987i.l, com.google.firebase.sessions.dagger.internal.a.a(AbstractC3997t.b), 0));
        return c3987i;
    }

    @Override // com.google.firebase.components.ComponentRegistrar
    @NotNull
    public List<com.google.firebase.components.a> getComponents() {
        C2537qm c2537qmB = com.google.firebase.components.a.b(C3994p.class);
        c2537qmB.a = LIBRARY_NAME;
        c2537qmB.a(com.google.firebase.components.j.b(firebaseSessionsComponent));
        c2537qmB.f = new com.google.firebase.components.n(26);
        c2537qmB.c(2);
        com.google.firebase.components.a aVarB = c2537qmB.b();
        C2537qm c2537qmB2 = com.google.firebase.components.a.b(InterfaceC3996s.class);
        c2537qmB2.a = "fire-sessions-component";
        c2537qmB2.a(com.google.firebase.components.j.b(appContext));
        c2537qmB2.a(com.google.firebase.components.j.b(backgroundDispatcher));
        c2537qmB2.a(com.google.firebase.components.j.b(blockingDispatcher));
        c2537qmB2.a(com.google.firebase.components.j.b(firebaseApp));
        c2537qmB2.a(com.google.firebase.components.j.b(firebaseInstallationsApi));
        c2537qmB2.a(new com.google.firebase.components.j(transportFactory, 1, 1));
        c2537qmB2.f = new com.google.firebase.components.n(27);
        return kotlin.collections.B.j(aVarB, c2537qmB2.b(), AbstractC3700q.a(LIBRARY_NAME, "2.1.1"));
    }
}
