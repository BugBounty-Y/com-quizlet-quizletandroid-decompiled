package com.google.android.gms.internal.ads;

import com.quizlet.data.exceptions.folder.FolderDoesNotExistException;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.BasicCourseFolder;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.FullCourseFolder;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Ns implements io.reactivex.rxjava3.functions.h {
    public final String a;
    public final long b;

    public Ns() {
        this.a = null;
        this.b = -1L;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Object objN;
        AbstractC4119d0 folder = (AbstractC4119d0) obj;
        Intrinsics.checkNotNullParameter(folder, "folder");
        if (!(folder instanceof CreatedFolder)) {
            return io.reactivex.rxjava3.core.p.d(new FolderDoesNotExistException(this.b));
        }
        CreatedFolder createdFolder = (CreatedFolder) folder;
        createdFolder.getClass();
        String name = this.a;
        Intrinsics.checkNotNullParameter(name, "name");
        if (createdFolder instanceof ContentFolder) {
            objN = ContentFolder.l((ContentFolder) createdFolder, 0L, name, null, 32687);
        } else if (createdFolder instanceof BasicCourseFolder) {
            objN = BasicCourseFolder.n((BasicCourseFolder) createdFolder, 0L, name, 16239);
        } else {
            if (!(createdFolder instanceof FullCourseFolder)) {
                throw new NoWhenBranchMatchedException();
            }
            objN = FullCourseFolder.n((FullCourseFolder) createdFolder, 0L, name, 32623);
        }
        return io.reactivex.rxjava3.core.p.f(objN);
    }

    public /* synthetic */ Ns(String str, long j) {
        this.a = str;
        this.b = j;
    }
}
