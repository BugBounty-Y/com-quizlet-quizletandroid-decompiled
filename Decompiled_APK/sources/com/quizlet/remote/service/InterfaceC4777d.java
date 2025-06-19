package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.classmembership.ClassMembershipsResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* renamed from: com.quizlet.remote.service.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC4777d {
    @retrofit2.http.f("class-memberships")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<ClassMembershipsResponse>> a(@retrofit2.http.t("filters[userId]") long j, @retrofit2.http.t("filters[isDeleted]") Boolean bool);
}
