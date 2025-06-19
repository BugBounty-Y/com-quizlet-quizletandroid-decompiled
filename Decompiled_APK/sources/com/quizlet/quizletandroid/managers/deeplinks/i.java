package com.quizlet.quizletandroid.managers.deeplinks;

import androidx.glance.appwidget.protobuf.Z;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ l j;
    public final /* synthetic */ String k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(l lVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = lVar;
        this.k = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        h hVar = this.j.c;
        String input = this.k;
        Intrinsics.checkNotNullParameter(input, "input");
        URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(new URL(input).openConnection());
        HttpURLConnection httpURLConnection = uRLConnection instanceof HttpURLConnection ? (HttpURLConnection) uRLConnection : null;
        if (httpURLConnection != null) {
            httpURLConnection.setInstanceFollowRedirects(false);
        }
        if (httpURLConnection != null) {
            return httpURLConnection.getHeaderField("Location");
        }
        return null;
    }
}
