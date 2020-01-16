namespace CrimsonDev.Gameteki.Api.Scheduler
{
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Hosting;
    using Quartz;
    using Quartz.Impl;
    using Quartz.Spi;

    public class SchedulerService : IHostedService
    {
        private readonly IJobFactory jobFactory;

        public SchedulerService(IJobFactory jobFactory)
        {
            this.jobFactory = jobFactory;
        }

        public IScheduler Scheduler { get; private set; }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            ISchedulerFactory schedulerFactory = new StdSchedulerFactory();
            Scheduler = await schedulerFactory.GetScheduler(cancellationToken);

            Scheduler.JobFactory = jobFactory;

            var job = JobBuilder.Create<NodeMonitor>().WithIdentity("NodeMonitor").Build();
            var trigger = TriggerBuilder
                .Create()
                .WithIdentity("NodeMonitorTrigger")
                .WithSimpleSchedule(x => x.WithIntervalInSeconds(30).RepeatForever())
                .Build();

            await Scheduler.ScheduleJob(job, trigger, cancellationToken);

            await Scheduler.Start(cancellationToken);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            if (Scheduler != null)
            {
                await Scheduler.Shutdown(true, cancellationToken);
            }
        }
    }
}