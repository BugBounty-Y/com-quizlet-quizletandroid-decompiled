package com.braze.communication.dust;

import androidx.glance.appwidget.protobuf.Z;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ String a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.a, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new f(this.a, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(new URL(this.a).openConnection());
        uRLConnection.setRequestProperty("Accept", "text/event-stream");
        uRLConnection.setDoInput(true);
        uRLConnection.connect();
        return uRLConnection;
    }
}
