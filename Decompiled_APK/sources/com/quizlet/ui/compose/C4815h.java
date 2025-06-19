package com.quizlet.ui.compose;

import com.quizlet.eventlogger.features.search.SearchType;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.ui.compose.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4815h {
    public final String a;
    public final SearchType b;
    public final androidx.compose.runtime.internal.d c;

    public C4815h(String title, SearchType searchType, androidx.compose.runtime.internal.d screen) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(screen, "screen");
        this.a = title;
        this.b = searchType;
        this.c = screen;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4815h)) {
            return false;
        }
        C4815h c4815h = (C4815h) obj;
        return Intrinsics.b(this.a, c4815h.a) && Intrinsics.b(this.b, c4815h.b) && Intrinsics.b(this.c, c4815h.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        SearchType searchType = this.b;
        return this.c.hashCode() + ((iHashCode + (searchType == null ? 0 : searchType.hashCode())) * 31);
    }

    public final String toString() {
        return "ComposeTabItem(title=" + this.a + ", loggingData=" + this.b + ", screen=" + this.c + ")";
    }
}
