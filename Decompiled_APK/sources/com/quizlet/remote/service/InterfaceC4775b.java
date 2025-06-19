package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.bookmark.BookmarkResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4775b {
    @retrofit2.http.f("bookmarks")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<BookmarkResponse>> a(@retrofit2.http.t("filters[folderId]") String str, @retrofit2.http.t("filters[personId]") String str2);
}
