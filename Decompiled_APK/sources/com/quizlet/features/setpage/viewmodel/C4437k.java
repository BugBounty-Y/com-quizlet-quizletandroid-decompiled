package com.quizlet.features.setpage.viewmodel;

import android.content.Context;
import android.content.res.Resources;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.viewmodel.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4437k implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.i, com.quizlet.features.setpage.utils.links.a {
    public static final C4437k b = new C4437k(0);
    public static final C4437k c = new C4437k(1);
    public static final C4437k d = new C4437k(2);
    public final /* synthetic */ int a;

    public /* synthetic */ C4437k(int i) {
        this.a = i;
    }

    @Override // com.quizlet.features.setpage.utils.links.a
    public String a(Context context, String url, String studySetTitle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(studySetTitle, "studySetTitle");
        String string = context.getResources().getString(R.string.share_message, studySetTitle, url);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Boolean canShareEmail = (Boolean) obj;
                Intrinsics.checkNotNullParameter(canShareEmail, "canShareEmail");
                return canShareEmail.booleanValue() ? com.quizlet.features.infra.basestudy.data.models.shareset.a.b : com.quizlet.features.infra.basestudy.data.models.shareset.a.d;
            default:
                DBStudySet it2 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                String webUrl = it2.getWebUrl();
                return webUrl == null ? "" : webUrl;
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        com.quizlet.features.infra.basestudy.data.models.shareset.a it2 = (com.quizlet.features.infra.basestudy.data.models.shareset.a) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2 != com.quizlet.features.infra.basestudy.data.models.shareset.a.d;
    }
}
