package com.quizlet.remote.model.folder.course;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SaveCourseToFolderRequestBody {
    public final long a;
    public final long b;
    public final boolean c;

    public SaveCourseToFolderRequestBody(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2, @InterfaceC4853h(name = "shouldReplace") boolean z) {
        this.a = j;
        this.b = j2;
        this.c = z;
    }

    @NotNull
    public final SaveCourseToFolderRequestBody copy(@InterfaceC4853h(name = "courseId") long j, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) long j2, @InterfaceC4853h(name = "shouldReplace") boolean z) {
        return new SaveCourseToFolderRequestBody(j, j2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SaveCourseToFolderRequestBody)) {
            return false;
        }
        SaveCourseToFolderRequestBody saveCourseToFolderRequestBody = (SaveCourseToFolderRequestBody) obj;
        return this.a == saveCourseToFolderRequestBody.a && this.b == saveCourseToFolderRequestBody.b && this.c == saveCourseToFolderRequestBody.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SaveCourseToFolderRequestBody(courseId=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", shouldReplace=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
