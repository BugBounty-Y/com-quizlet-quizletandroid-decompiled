package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderCopyEligibilityResponse;
import com.quizlet.remote.model.folder.FolderResponse;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.folder.SubfolderNameRecommendationsResponse;
import com.quizlet.remote.model.folder.course.CourseStudyMaterialRecommendationsResponse;
import com.quizlet.remote.model.union.folderwithcreator.FolderWithCreatorResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface m {
    @retrofit2.http.o("folders/{folderIds}/copy")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderResponse>> a(@retrofit2.http.s("folderIds") long j);

    @retrofit2.http.f("folders/{folderIds}/subfolder-names-recommendations")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<SubfolderNameRecommendationsResponse>> b(@retrofit2.http.s("folderIds") long j);

    @retrofit2.http.f("folders/{folderIds}/copy-eligibility")
    @NotNull
    io.reactivex.rxjava3.core.p<FolderCopyEligibilityResponse> c(@retrofit2.http.s("folderIds") long j);

    @retrofit2.http.f("folders/{folderIds}/course-study-material-recommendations")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<CourseStudyMaterialRecommendationsResponse>> d(@retrofit2.http.s("folderIds") @NotNull String str);

    @retrofit2.http.o("folders/save")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderResponse>> e(@NotNull @retrofit2.http.a ApiPostBody<RemoteFolder> apiPostBody);

    @retrofit2.http.o("folders/{folderIds}/subfolder")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderResponse>> f(@retrofit2.http.s("folderIds") long j, @NotNull @retrofit2.http.a ApiPostBody<String> apiPostBody);

    @retrofit2.http.f("folders/{folderIds}?include[folder][]=user")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderWithCreatorResponse>> g(@retrofit2.http.s("folderIds") @NotNull String str, @retrofit2.http.t("filters[isHidden]") boolean z);

    @retrofit2.http.b("folders/{folderIds}")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderResponse>> h(@retrofit2.http.s("folderIds") @NotNull String str);

    @retrofit2.http.f("folders/{folderIds}?include[folder][]=user&include[folder][]=course&include[folder][]=school")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderWithCreatorResponse>> i(@retrofit2.http.s("folderIds") long j);

    @retrofit2.http.f("folders?include[folder][]=user")
    @NotNull
    io.reactivex.rxjava3.core.p<ApiThreeWrapper<FolderWithCreatorResponse>> j(@retrofit2.http.t("filters[personId]") String str, @retrofit2.http.t("filters[isHidden]") boolean z);
}
