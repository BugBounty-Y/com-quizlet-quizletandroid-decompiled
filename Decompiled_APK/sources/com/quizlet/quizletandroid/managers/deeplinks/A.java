package com.quizlet.quizletandroid.managers.deeplinks;

import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A extends o {
    public static final String b;
    public final String a;

    static {
        String simpleName = A.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public A(String textbookIsbn) {
        Intrinsics.checkNotNullParameter(textbookIsbn, "textbookIsbn");
        this.a = textbookIsbn;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = TextbookActivity.r;
        String isbn = this.a;
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intent[] intents = TaskStackBuilder.create(context).addNextIntentWithParentStack(okhttp3.internal.platform.m.c(context, new TextbookSetUpState.TableOfContents(isbn))).getIntents();
        Intrinsics.checkNotNullExpressionValue(intents, "getIntents(...)");
        return intents;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A) && Intrinsics.b(this.a, ((A) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("TextbookTableOfContentsDeepLink(textbookIsbn="), this.a, ")");
    }
}
