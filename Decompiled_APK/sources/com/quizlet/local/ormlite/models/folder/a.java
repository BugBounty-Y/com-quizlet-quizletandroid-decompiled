package com.quizlet.local.ormlite.models.folder;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.BasicCourseFolder;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.J;
import com.quizlet.data.model.P;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.generated.enums.L0;
import com.quizlet.generated.enums.M0;
import com.quizlet.local.ormlite.util.c;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, c {
    public static final a b = new a(0);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static DBFolder a(AbstractC4119d0 data) {
        Intrinsics.checkNotNullParameter(data, "data");
        DBFolder dBFolderCreate = DBFolder.create(0L, "", "");
        dBFolderCreate.setId(data.a());
        dBFolderCreate.setLocalId(data.c());
        dBFolderCreate.setLastModified(data.b());
        dBFolderCreate.setDeleted(data.d());
        dBFolderCreate.setDirty(data.e());
        if (data instanceof CreatedFolder) {
            CreatedFolder createdFolder = (CreatedFolder) data;
            dBFolderCreate.setName(createdFolder.g());
            dBFolderCreate.setPersonId(createdFolder.h());
            dBFolderCreate.setTimestamp(createdFolder.i());
            dBFolderCreate.setWebUrl(createdFolder.j());
            dBFolderCreate.setIsHidden(createdFolder.k());
            Long lF = createdFolder.f();
            dBFolderCreate.setClientTimestamp(lF != null ? lF.longValue() : 0L);
        }
        if (data instanceof ContentFolder) {
            ContentFolder contentFolder = (ContentFolder) data;
            dBFolderCreate.setDescription(contentFolder.s);
            dBFolderCreate.setNumStudySets(contentFolder.x);
            dBFolderCreate.setIsCoursePowered(false);
            dBFolderCreate.setSchoolCourseDescription(null);
        } else if (data instanceof J) {
            dBFolderCreate.setIsCoursePowered(true);
            J j = (J) data;
            dBFolderCreate.setSchoolCourseDescription(j.m());
            M0 m0L = j.l();
            dBFolderCreate.setQpfGenerationMethod(m0L != null ? m0L.a() : 0);
        }
        Intrinsics.checkNotNullExpressionValue(dBFolderCreate, "apply(...)");
        return dBFolderCreate;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List<DBFolder> localFolder = (List) obj;
        Intrinsics.checkNotNullParameter(localFolder, "localFolder");
        int iA = U.a(C.q(localFolder, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (DBFolder dBFolder : localFolder) {
            linkedHashMap.put(Long.valueOf(dBFolder.getId()), Long.valueOf(dBFolder.getLocalId()));
        }
        return linkedHashMap;
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        switch (this.a) {
        }
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public Object h(Object obj) throws Exception {
        switch (this.a) {
            case 1:
                DBFolder local = (DBFolder) obj;
                Intrinsics.checkNotNullParameter(local, "local");
                if (local.getDeleted()) {
                    return new P(local.getDeleted(), local.getId(), local.getLastModified(), local.getDirty(), local.getLocalId());
                }
                if (!local.getIsCoursePowered()) {
                    long id = local.getId();
                    long localId = local.getLocalId();
                    long personId = local.getPersonId();
                    String name = local.getName();
                    Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
                    String description = local.getDescription();
                    return new ContentFolder(id, local.getDeleted(), local.getLastModified(), localId, local.getDirty(), personId, name, description == null ? "" : description, local.getTimestamp(), local.getIsHidden(), local.getWebUrl(), Long.valueOf(local.getClientTimestamp()), local.getNumStudySets(), null, null, 24576, null);
                }
                long id2 = local.getId();
                boolean deleted = local.getDeleted();
                long lastModified = local.getLastModified();
                long localId2 = local.getLocalId();
                boolean dirty = local.getDirty();
                long personId2 = local.getPersonId();
                long timestamp = local.getTimestamp();
                String name2 = local.getName();
                Intrinsics.checkNotNullExpressionValue(name2, "getName(...)");
                boolean isHidden = local.getIsHidden();
                String webUrl = local.getWebUrl();
                Long lValueOf = Long.valueOf(local.getClientTimestamp());
                String schoolCourseDescription = local.getSchoolCourseDescription();
                String str = schoolCourseDescription == null ? "" : schoolCourseDescription;
                L0 l0 = M0.Companion;
                int qpfGenerationMethod = local.getQpfGenerationMethod();
                l0.getClass();
                M0[] m0ArrValues = M0.values();
                int length = m0ArrValues.length;
                int i = 0;
                while (i < length) {
                    M0 m0 = m0ArrValues[i];
                    int i2 = i;
                    if (m0.a() == qpfGenerationMethod) {
                        return new BasicCourseFolder(id2, deleted, lastModified, localId2, dirty, personId2, timestamp, name2, isHidden, webUrl, lValueOf, str, null, m0, 4096, null);
                    }
                    name2 = name2;
                    i = i2 + 1;
                }
                throw new NoSuchElementException("Array contains no element matching the predicate.");
            default:
                Intrinsics.checkNotNullParameter((DBFolder) obj, "local");
                throw new Exception("can't convert db folder to new folder");
        }
    }
}
