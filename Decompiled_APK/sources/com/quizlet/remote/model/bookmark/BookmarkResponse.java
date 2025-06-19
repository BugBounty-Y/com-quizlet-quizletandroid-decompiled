package com.quizlet.remote.model.bookmark;

import android.support.v4.media.session.a;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class BookmarkResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(@InterfaceC4853h(name = DBBookmark.TABLE_NAME) List<RemoteBookmark> list) {
            this.a = list;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = DBBookmark.TABLE_NAME) List<RemoteBookmark> list) {
            return new Models(list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Models) && Intrinsics.b(this.a, ((Models) obj).a);
        }

        public final int hashCode() {
            List list = this.a;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final String toString() {
            return a.n(")", new StringBuilder("Models(bookmark="), this.a);
        }
    }

    public BookmarkResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final BookmarkResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new BookmarkResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof BookmarkResponse) && Intrinsics.b(this.d, ((BookmarkResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "BookmarkResponse(models=" + this.d + ")";
    }
}
