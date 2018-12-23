namespace CrimsonDev.Gameteki.Api.Tests.Helpers
{
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Linq.Expressions;

    [ExcludeFromCodeCoverage]
    internal class AsyncEnumerable<T> : EnumerableQuery<T>, IAsyncEnumerable<T>
    {
        public AsyncEnumerable(Expression expression)
            : base(expression)
        {
        }

        public IAsyncEnumerator<T> GetEnumerator() => new AsyncEnumerator<T>(this.AsEnumerable().GetEnumerator());
    }
}
