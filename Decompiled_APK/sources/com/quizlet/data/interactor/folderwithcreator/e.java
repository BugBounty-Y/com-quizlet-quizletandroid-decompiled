package com.quizlet.data.interactor.folderwithcreator;

import com.quizlet.data.model.CreatedFolderWithCreator;
import java.util.Comparator;

/* loaded from: classes2.dex */
public final class e implements Comparator {
    public final /* synthetic */ int a;

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
        }
        return kotlin.comparisons.a.b(Long.valueOf(((CreatedFolderWithCreator) obj2).a.b()), Long.valueOf(((CreatedFolderWithCreator) obj).a.b()));
    }
}
