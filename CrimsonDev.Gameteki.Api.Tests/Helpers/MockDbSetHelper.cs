namespace CrimsonDev.Gameteki.Api.Tests.Helpers
{
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using Microsoft.EntityFrameworkCore;
    using Moq;

    [ExcludeFromCodeCoverage]
    public static class MockDbSetHelper
    {
        public static Mock<DbSet<T>> ToMockDbSet<T>(this IQueryable<T> source)
            where T : class
        {
            var mockSet = new Mock<DbSet<T>>();

            mockSet.As<IAsyncEnumerable<T>>()
                .Setup(m => m.GetEnumerator())
                .Returns(new AsyncEnumerator<T>(source.GetEnumerator()));

            mockSet.As<IQueryable<T>>()
                .Setup(m => m.Provider)
                .Returns(new AsyncQueryProvider<T>(source.Provider));

            mockSet.As<IQueryable<T>>().Setup(m => m.Expression).Returns(source.Expression);
            mockSet.As<IQueryable<T>>().Setup(m => m.ElementType).Returns(source.ElementType);
            mockSet.As<IQueryable<T>>().Setup(m => m.GetEnumerator()).Returns(source.GetEnumerator());

            return mockSet;
        }

        public static Mock<DbSet<T>> ToMockDbSet<T>(this IList<T> source)
            where T : class
        {
            return source.AsQueryable().ToMockDbSet();
        }
    }
}
