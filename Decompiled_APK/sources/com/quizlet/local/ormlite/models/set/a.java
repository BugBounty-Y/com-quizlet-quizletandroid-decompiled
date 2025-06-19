package com.quizlet.local.ormlite.models.set;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.quizlet.data.model.StudySet;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.local.ormlite.util.c;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, c {
    public static final a a = new a();

    public static StudySet a(DBStudySet local) {
        Intrinsics.checkNotNullParameter(local, "local");
        long id = local.getId();
        int timestamp = (int) local.getTimestamp();
        int lastModified = (int) local.getLastModified();
        int publishedTimestamp = (int) local.getPublishedTimestamp();
        long creatorId = local.getCreatorId();
        String wordLang = local.getWordLang();
        Intrinsics.checkNotNullExpressionValue(wordLang, "getWordLang(...)");
        String defLang = local.getDefLang();
        Intrinsics.checkNotNullExpressionValue(defLang, "getDefLang(...)");
        String title = local.getTitle();
        if (title == null) {
            title = "";
        }
        boolean passwordUse = local.getPasswordUse();
        boolean passwordEdit = local.getPasswordEdit();
        int accessType = local.getAccessType();
        String acccessCodePrefix = local.getAcccessCodePrefix();
        String description = local.getDescription();
        if (description == null) {
            description = "";
        }
        int numTerms = local.getNumTerms();
        boolean hasImages = local.getHasImages();
        String str = title;
        int parentId = (int) local.getParentId();
        int creationSource = local.getCreationSource();
        int privacyLockStatus = local.getPrivacyLockStatus();
        boolean hasDiagrams = local.getHasDiagrams();
        String webUrl = local.getWebUrl();
        if (webUrl == null) {
            webUrl = "";
        }
        return new StudySet(id, timestamp, lastModified, publishedTimestamp, creatorId, wordLang, defLang, str, passwordUse, passwordEdit, accessType, acccessCodePrefix, description, numTerms, hasImages, parentId, creationSource, privacyLockStatus, hasDiagrams, webUrl, local.getThumbnailUrl(), null, 0, local.getLocalId(), local.getDeleted(), Long.valueOf(local.getClientTimestamp()), local.getDirty(), local.getReadyToCreate(), null, 268435456, null);
    }

    public static DBStudySet b(StudySet data) {
        Intrinsics.checkNotNullParameter(data, "data");
        DBStudySet dBStudySet = new DBStudySet();
        dBStudySet.setId(data.a);
        dBStudySet.setTimestamp(data.b);
        dBStudySet.setLastModified(data.c);
        dBStudySet.setPublishedTimestamp(Long.valueOf(data.d));
        dBStudySet.setCreatorId(data.e);
        dBStudySet.setWordLang(data.f);
        dBStudySet.setDefLang(data.g);
        dBStudySet.setTitle(data.h);
        dBStudySet.setPasswordUse(data.i);
        dBStudySet.setPasswordEdit(data.j);
        dBStudySet.setAccessType(data.k);
        dBStudySet.setAccessCodePrefix(data.l);
        dBStudySet.setDescription(data.m);
        dBStudySet.setNumTerms(data.n);
        dBStudySet.setHasImages(Boolean.valueOf(data.o));
        dBStudySet.setParentId(data.p);
        dBStudySet.setCreationSource(data.q);
        dBStudySet.setPrivacyLockStatus(data.r);
        dBStudySet.setHasDiagrams(data.s);
        dBStudySet.setWebUrl(data.t);
        dBStudySet.setThumbnailUrl(data.u);
        dBStudySet.setLocalId(data.x);
        dBStudySet.setDeleted(data.y);
        Long l = data.z;
        dBStudySet.setClientTimestamp(l != null ? l.longValue() : 0L);
        dBStudySet.setDirty(data.A);
        dBStudySet.setReadyToCreate(data.B);
        return dBStudySet;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List<DBStudySet> localStudySet = (List) obj;
        Intrinsics.checkNotNullParameter(localStudySet, "localStudySet");
        int iA = U.a(C.q(localStudySet, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (DBStudySet dBStudySet : localStudySet) {
            linkedHashMap.put(Long.valueOf(dBStudySet.getId()), Long.valueOf(dBStudySet.getLocalId()));
        }
        return linkedHashMap;
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return a((DBStudySet) obj);
    }
}
