namespace CrimsonDev.Gameteki.Api.Scheduler
{
    using System;
    using Quartz;
    using Quartz.Spi;

    public class JobFactory : IJobFactory
    {
        private readonly IServiceProvider container;

        public JobFactory(IServiceProvider container)
        {
            this.container = container;
        }

        public IJob NewJob(TriggerFiredBundle bundle, IScheduler scheduler)
        {
            if (bundle == null)
            {
                throw new ArgumentNullException(nameof(bundle));
            }

            return container.GetService(bundle.JobDetail.JobType) as IJob;
        }

        public void ReturnJob(IJob job)
        {
            // Not implemented / needed
        }
    }
}
