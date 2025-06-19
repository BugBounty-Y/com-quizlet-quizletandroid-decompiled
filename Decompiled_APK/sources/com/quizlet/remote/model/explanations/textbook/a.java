package com.quizlet.remote.model.explanations.textbook;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.interactor.school.b;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.X;
import com.quizlet.data.model.k2;
import com.quizlet.quizletandroid.k;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.textbook.TextbookResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ b a;
    public final /* synthetic */ String b;

    public a(b bVar, String str) {
        this.a = bVar;
        this.b = str;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        TextbookResponse.Models models;
        List remotes;
        RemoteMeteringInfo remoteMeteringInfo;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        TextbookResponse textbookResponse = (TextbookResponse) response.a();
        b bVar = this.a;
        Textbook textbook = null;
        X xB = (textbookResponse == null || (remoteMeteringInfo = textbookResponse.e) == null) ? null : com.quizlet.quizletandroid.logging.initializer.a.b(remoteMeteringInfo);
        TextbookResponse textbookResponse2 = (TextbookResponse) response.a();
        if (textbookResponse2 != null && (models = textbookResponse2.d) != null && (remotes = models.a) != null) {
            k kVar = (k) bVar.c;
            Intrinsics.checkNotNullParameter(remotes, "remotes");
            textbook = (Textbook) CollectionsKt.firstOrNull(S.f(kVar, remotes));
        }
        return textbook != null ? p.f(new k2(textbook, xB)) : p.d(new NoSuchElementException(android.support.v4.media.session.a.t(new StringBuilder("No textbook found with isbn ("), this.b, ")")));
    }
}
