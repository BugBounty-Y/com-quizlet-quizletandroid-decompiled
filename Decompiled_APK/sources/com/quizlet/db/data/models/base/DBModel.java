package com.quizlet.db.data.models.base;

import com.quizlet.data.model.C4115c0;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.Comparator;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.F;
import kotlin.comparisons.a;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public interface DBModel {

    @NotNull
    public static final Companion Companion = Companion.$$INSTANCE;

    @Metadata
    public static final class Companion {
        static final /* synthetic */ Companion $$INSTANCE = new Companion();

        private Companion() {
        }

        @InterfaceC4935d
        public final <M extends DBModel> void sort(@NotNull List<M> items) {
            Intrinsics.checkNotNullParameter(items, "items");
            F.t(items, Comparators.DEFAULT_ASC);
        }

        public final <M extends DBModel> void sortByTimestamp(@NotNull List<M> items) {
            Intrinsics.checkNotNullParameter(items, "items");
            if (items.size() > 1) {
                F.t(items, new Comparator() { // from class: com.quizlet.db.data.models.base.DBModel$Companion$sortByTimestamp$$inlined$sortBy$1
                    @Override // java.util.Comparator
                    public final int compare(T t, T t2) {
                        long j = -1;
                        return a.b(Long.valueOf(((DBModel) t).getLastModified() * j), Long.valueOf(((DBModel) t2).getLastModified() * j));
                    }
                });
            }
        }

        @InterfaceC4935d
        public final <M extends DBModel> void sortReverse(@NotNull List<M> items) {
            Intrinsics.checkNotNullParameter(items, "items");
            F.t(items, Comparators.DEFAULT_DESC);
        }
    }

    <M extends DBModel> int compare(@NotNull M m, @NotNull M m2);

    long getClientTimestamp();

    boolean getDeleted();

    boolean getDirty();

    @NotNull
    List<C4115c0> getFilesForRequest();

    @NotNull
    <M extends DBModel> ModelIdentity<M> getIdentity();

    long getLastModified();

    long getLocalId();

    @NotNull
    <M extends DBModel> ModelType<M> getModelType();

    void setClientTimestamp(long j);

    void setDeleted(boolean z);

    void setDirty(boolean z);

    void setLastModified(long j);

    void setLocalId(long j);
}
